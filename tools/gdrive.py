import io
import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Optional

import click
import google.oauth2.credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

DRIVE_SCOPE_WRITE = 'https://www.googleapis.com/auth/drive'
DRIVE_SCOPE_READ = 'https://www.googleapis.com/auth/drive.readonly'


@dataclass
class DriveContext:
    """Cached Drive state from download, reused for upload to avoid re-traversal."""
    service: Any
    root_id: str
    root_name: str
    year_folders: dict         # year_str → folder_id
    curr_month_id: str
    curr_month_path: str       # e.g. "2026/2026-05"
    folder_ids: dict = field(default_factory=dict)  # logical_name → folder_id


def _get_token():
    try:
        return subprocess.check_output(
            ['gcloud', 'auth', 'print-access-token'], stderr=subprocess.DEVNULL
        ).decode().strip()
    except subprocess.CalledProcessError:
        raise click.ClickException(
            'Not logged in to gcloud. Run: gcloud auth login --enable-gdrive-access'
        )


def check_drive_auth():
    token = _get_token()
    url = f'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}'
    resp = urllib.request.urlopen(url)
    info = json.loads(resp.read())
    scopes = info.get('scope', '').split()
    if DRIVE_SCOPE_WRITE not in scopes:
        if DRIVE_SCOPE_READ in scopes:
            raise click.ClickException(
                'Google Drive credentials are read-only; write access is required for uploads.\n'
                'Run: gcloud auth login --enable-gdrive-access'
            )
        raise click.ClickException(
            'Google Drive scope not found in current credentials.\n'
            'Run: gcloud auth login --enable-gdrive-access'
        )
    return token


def _build_service(token):
    creds = google.oauth2.credentials.Credentials(token)
    return build('drive', 'v3', credentials=creds)


def _adjacent_months(today: date):
    """Return (next_month, current_month, prev_month) as first-of-month date objects."""
    first = today.replace(day=1)
    prev_first = (first - timedelta(days=1)).replace(day=1)
    next_first = (first + timedelta(days=32)).replace(day=1)
    return next_first, first, prev_first


def _find_subfolder(service, parent_id, name):
    escaped = name.replace("'", "\\'")
    results = service.files().list(
        q=f"'{parent_id}' in parents and mimeType='application/vnd.google-apps.folder' and name='{escaped}'",
        fields='files(id)'
    ).execute()
    files = results['files']
    return files[0]['id'] if files else None


def _list_files(service, folder_id):
    results = service.files().list(
        q=f"'{folder_id}' in parents and mimeType!='application/vnd.google-apps.folder'",
        fields='files(id, name, mimeType)'
    ).execute()
    return results['files']


def _parse_date_from_name(name: str) -> Optional[date]:
    # hail_report_20260514.csv  →  YYYYMMDD
    m = re.search(r'(\d{8})', name)
    if m:
        s = m.group(1)
        try:
            return date(int(s[:4]), int(s[4:6]), int(s[6:8]))
        except ValueError:
            pass
    # INTERNAL ... POAM - 2026-05-08.xlsx  →  YYYY-MM-DD
    m = re.search(r'(\d{4}-\d{2}-\d{2})', name)
    if m:
        try:
            return date.fromisoformat(m.group(1))
        except ValueError:
            pass
    return None


def _get_year_folders(service, root_id):
    """Return dict of year string → folder ID for all numeric-named subfolders."""
    results = service.files().list(
        q=f"'{root_id}' in parents and mimeType='application/vnd.google-apps.folder'",
        fields='files(id, name)'
    ).execute()
    return {f['name']: f['id'] for f in results['files'] if f['name'].isdigit()}


def _resolve_month_folder(service, year_folders, month_date: date):
    """Return (folder_id, display_path) for a given month, or (None, None)."""
    year_str = str(month_date.year)
    month_str = month_date.strftime('%Y-%m')
    year_id = year_folders.get(year_str)
    if not year_id:
        return None, None
    month_id = _find_subfolder(service, year_id, month_str)
    if not month_id:
        return None, None
    return month_id, f'{year_str}/{month_str}'


def _find_zap_file(service, year_folders, next_m, curr_m, prev_m):
    """Search next/current/prev months; return (file_id, name, date, display_path) for the latest CSV."""
    best = None
    for month_date in [next_m, curr_m, prev_m]:
        month_id, month_path = _resolve_month_folder(service, year_folders, month_date)
        if not month_id:
            continue
        vuln_id = _find_subfolder(service, month_id, 'Vulnerability Reports')
        if not vuln_id:
            continue
        zap_id = _find_subfolder(service, vuln_id, 'Zap')
        if not zap_id:
            continue
        raw_id = _find_subfolder(service, zap_id, 'Raw Reports')
        if not raw_id:
            continue
        for f in _list_files(service, raw_id):
            if not f['name'].endswith('.csv'):
                continue
            d = _parse_date_from_name(f['name'])
            if d and (best is None or d > best[2]):
                full_path = f'{month_path}/Vulnerability Reports/Zap/Raw Reports/{f["name"]}'
                best = (f['id'], f['name'], d, full_path)
    return best


def _find_poam_file(service, year_folders, curr_m, prev_m):
    """Search current then prev month; return (file_id, name, date, display_path) for latest INTERNAL POAM."""
    for month_date in [curr_m, prev_m]:
        month_id, month_path = _resolve_month_folder(service, year_folders, month_date)
        if not month_id:
            continue
        poam_id = _find_subfolder(service, month_id, 'Plan of Action and Milestones')
        if not poam_id:
            continue
        candidates = []
        for f in _list_files(service, poam_id):
            if 'INTERNAL' not in f['name'] or not f['name'].endswith('.xlsx'):
                continue
            d = _parse_date_from_name(f['name'])
            if d:
                full_path = f'{month_path}/Plan of Action and Milestones/{f["name"]}'
                candidates.append((f['id'], f['name'], d, full_path))
        if candidates:
            return max(candidates, key=lambda x: x[2])
    return None


def _find_cis_sheet(service, root_id):
    """Find the Google Sheet in Scans (Ongoing)/; return (file_id, safe_local_name, display_path)."""
    scans_id = _find_subfolder(service, root_id, 'Scans (Ongoing)')
    if not scans_id:
        return None
    results = service.files().list(
        q=f"'{scans_id}' in parents and mimeType='application/vnd.google-apps.spreadsheet'",
        fields='files(id, name)'
    ).execute()
    files = results['files']
    if not files:
        return None
    f = files[0]
    safe_name = f['name'].replace('/', '_') + '.xlsx'
    return f['id'], safe_name, f'Scans (Ongoing)/{f["name"]}'


def _download_binary(service, file_id, dest: Path):
    request = service.files().get_media(fileId=file_id)
    buf = io.BytesIO()
    dl = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _, done = dl.next_chunk()
    dest.write_bytes(buf.getvalue())


def _export_sheet_xlsx(service, file_id, dest: Path):
    mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    request = service.files().export_media(fileId=file_id, mimeType=mime)
    buf = io.BytesIO()
    dl = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _, done = dl.next_chunk()
    dest.write_bytes(buf.getvalue())


def _upload_file(service, folder_id, local_path: Path, mime_type: str):
    media = MediaFileUpload(str(local_path), mimetype=mime_type)
    service.files().create(
        body={'name': local_path.name, 'parents': [folder_id]},
        media_body=media,
        fields='id'
    ).execute()


def download_scan_inputs(working_dir: Path, drive_folder_id: str) -> tuple[Path, Path, Path, DriveContext]:
    token = check_drive_auth()
    service = _build_service(token)

    today = date.today()
    next_m, curr_m, prev_m = _adjacent_months(today)

    click.echo('Scanning Google Drive folders...')
    root_meta = service.files().get(fileId=drive_folder_id, fields='name').execute()
    root_name = root_meta['name']
    year_folders = _get_year_folders(service, drive_folder_id)

    zap = _find_zap_file(service, year_folders, next_m, curr_m, prev_m)
    poam = _find_poam_file(service, year_folders, curr_m, prev_m)
    cis = _find_cis_sheet(service, drive_folder_id)

    # Resolve curr_month folder and cache upload-relevant subfolder IDs
    curr_month_id, curr_month_path = _resolve_month_folder(service, year_folders, curr_m)
    folder_ids = {}
    if curr_month_id:
        vuln_id = _find_subfolder(service, curr_month_id, 'Vulnerability Reports')
        if vuln_id:
            folder_ids['vuln'] = vuln_id
            cis_upload_id = _find_subfolder(service, vuln_id, 'CIS')
            if cis_upload_id:
                folder_ids['cis_upload'] = cis_upload_id
            trivy_upload_id = _find_subfolder(service, vuln_id, 'Trivy')
            if trivy_upload_id:
                folder_ids['trivy_upload'] = trivy_upload_id
        poam_upload_id = _find_subfolder(service, curr_month_id, 'Plan of Action and Milestones')
        if poam_upload_id:
            folder_ids['poam_upload'] = poam_upload_id

    ctx = DriveContext(
        service=service,
        root_id=drive_folder_id,
        root_name=root_name,
        year_folders=year_folders,
        curr_month_id=curr_month_id,
        curr_month_path=curr_month_path,
        folder_ids=folder_ids,
    )

    click.echo('\nI\'m about to download these files:')
    if zap:
        click.echo(f'  ZAP:  {root_name}/{zap[3]}')
        click.echo(f'      → {working_dir / zap[1]}')
    else:
        click.echo('  ZAP:  *** NOT FOUND ***')
    if poam:
        click.echo(f'  POAM: {root_name}/{poam[3]}')
        click.echo(f'      → {working_dir / poam[1]}')
    else:
        click.echo('  POAM: *** NOT FOUND ***')
    if cis:
        click.echo(f'  CIS:  {root_name}/{cis[2]}')
        click.echo(f'      → {working_dir / cis[1]}')
    else:
        click.echo('  CIS:  *** NOT FOUND ***')

    warnings = []
    if zap:
        age = (today - zap[2]).days
        if age > 7:
            warnings.append(f'  ⚠️  WARNING: ZAP scan is {age} days old — may be stale.')
    if not zap:
        warnings.append('  ⚠️  ZAP file not found in next/current/previous month folders.')
    if not poam:
        warnings.append('  ⚠️  INTERNAL POAM file not found in current/previous month folders.')
    if not cis:
        warnings.append('  ⚠️  CIS sheet not found in Scans (Ongoing)/.')

    if warnings:
        click.echo('')
        for w in warnings:
            click.echo(w)

    if not zap or not poam or not cis:
        raise click.ClickException('Required files not found; cannot proceed.')

    click.confirm('\nContinue?', default=True, abort=True)

    working_dir.mkdir(parents=True, exist_ok=True)

    zap_dest = working_dir / zap[1]
    click.echo(f'\nDownloading ZAP:  {zap[1]}')
    _download_binary(service, zap[0], zap_dest)

    poam_dest = working_dir / poam[1]
    click.echo(f'Downloading POAM: {poam[1]}')
    _download_binary(service, poam[0], poam_dest)

    cis_dest = working_dir / cis[1]
    click.echo(f'Downloading CIS:  {cis[1]}')
    _export_sheet_xlsx(service, cis[0], cis_dest)

    click.echo('\nAll files downloaded successfully.')
    return zap_dest, poam_dest, cis_dest, ctx


def upload_scan_outputs(working_dir: Path, ctx: DriveContext):
    service = ctx.service
    today = date.today()
    today_str = today.isoformat()

    # Identify the three files to upload
    cis_scans_dir = working_dir / 'Divided CIS Scans'
    cis_csvs = sorted(cis_scans_dir.glob('*.csv')) if cis_scans_dir.exists() else []
    cis_local = max(cis_csvs, key=lambda f: f.name) if cis_csvs else None

    trivy_local = working_dir / f'trivy-findings-{today_str}.findings.csv'
    if not trivy_local.exists():
        trivy_local = None

    poam_candidates = sorted(working_dir.glob('INTERNAL Hail Plan of Action & Milestones (POAM) - *.xlsx'))
    poam_local = max(poam_candidates, key=lambda f: f.name) if poam_candidates else None
    # Prefer today's file if it exists
    poam_today = working_dir / f'INTERNAL Hail Plan of Action & Milestones (POAM) - {today_str}.xlsx'
    if poam_today.exists():
        poam_local = poam_today

    base = ctx.curr_month_path  # e.g. "2026/2026-05"

    click.echo('\nI\'m about to upload these files:')
    if cis_local:
        dest_path = f'{ctx.root_name}/{base}/Vulnerability Reports/CIS/{cis_local.name}'
        click.echo(f'  CIS:   {cis_local}')
        click.echo(f'       → {dest_path}')
    else:
        click.echo('  CIS:   *** NOT FOUND in Divided CIS Scans/ ***')

    if trivy_local:
        dest_path = f'{ctx.root_name}/{base}/Vulnerability Reports/Trivy/{trivy_local.name}'
        click.echo(f'  Trivy: {trivy_local}')
        click.echo(f'       → {dest_path}')
    else:
        click.echo(f'  Trivy: *** NOT FOUND (trivy-findings-{today_str}.findings.csv) ***')

    if poam_local:
        dest_path = f'{ctx.root_name}/{base}/Plan of Action and Milestones/{poam_local.name}'
        click.echo(f'  POAM:  {poam_local}')
        click.echo(f'       → {dest_path}')
    else:
        click.echo('  POAM:  *** NOT FOUND ***')

    missing_files = [name for name, f in [('CIS', cis_local), ('Trivy', trivy_local), ('POAM', poam_local)] if not f]
    if missing_files:
        click.echo(f'\n  ⚠️  Missing local files: {", ".join(missing_files)}')
        raise click.ClickException('Required output files not found; cannot upload.')

    missing_folders = [k for k in ('cis_upload', 'trivy_upload', 'poam_upload') if k not in ctx.folder_ids]
    if missing_folders:
        labels = {'cis_upload': 'Vulnerability Reports/CIS', 'trivy_upload': 'Vulnerability Reports/Trivy', 'poam_upload': 'Plan of Action and Milestones'}
        click.echo(f'\n  ⚠️  Destination folders not found in Drive: {", ".join(labels[k] for k in missing_folders)}')
        raise click.ClickException('Required Drive destination folders not found; cannot upload.')

    click.confirm('\nContinue?', default=True, abort=True)

    xlsx_mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    click.echo(f'\nUploading CIS:   {cis_local.name}')
    _upload_file(service, ctx.folder_ids['cis_upload'], cis_local, 'text/csv')

    click.echo(f'Uploading Trivy: {trivy_local.name}')
    _upload_file(service, ctx.folder_ids['trivy_upload'], trivy_local, 'text/csv')

    click.echo(f'Uploading POAM:  {poam_local.name}')
    _upload_file(service, ctx.folder_ids['poam_upload'], poam_local, xlsx_mime)

    click.echo('\nAll files uploaded successfully.')
