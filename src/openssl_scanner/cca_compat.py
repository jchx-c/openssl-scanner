"""Load CCA interface data from JSON and append comparison reports."""

import csv
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_CCA_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'cca_compat.json'))
CCA_SHEET_NAME = 'CCA Compatibility'
_CCA_SHEET_NAMES = (CCA_SHEET_NAME, 'cca兼容性')
SCAN_CONCLUSION_SHEET_NAME = 'Scan Conclusion'
CCA_NO_IMPACT_CONCLUSION = '接口一致无感知'
CCA_NO_ANALYSIS_CONCLUSION = '暂无分析结论'
PROVIDER_LOAD_APIS = frozenset({
    'OSSL_PROVIDER_load',
    'OSSL_PROVIDER_load_ex',
    'OSSL_PROVIDER_try_load',
    'OSSL_PROVIDER_try_load_ex',
})

_SYMBOL_HEADERS = {
    "openssl接口", "openssl接口名", "openssl接口名称", "openssl函数",
    "openssl函数名", "opensslapi", "opensslapiname", "opensslsymbol",
    "接口", "接口名", "接口名称", "函数名", "函数名称",
}
_CONCLUSION_HEADERS = {
    "cca兼容性情况", "兼容性情况",
    "cca兼容性结论", "兼容性结论", "兼容性分析结论", "cca兼容性",
    "兼容性", "结论", "compatibilityconclusion", "ccacompatibility",
}


@dataclass(frozen=True)
class CCAEntry:
    symbol: str
    conclusion: Optional[str]
    sheet: str
    row: int
    scenarios: Optional[str] = None
    difference_description: Optional[str] = None


def _header(value) -> str:
    return re.sub(r"[\s_\-]+", "", str(value or "")).lower()


def is_custom_category(category) -> bool:
    return str(category or '').strip().upper() in {'CUSTOM', 'SELF'}


def codebook_path(report_path) -> str:
    return os.path.splitext(os.fspath(report_path))[0] + '_cca_codes.txt'


def _report_scan_target(report_path) -> str:
    json_path = os.path.splitext(os.fspath(report_path))[0] + '.json'
    if not os.path.isfile(json_path):
        return ''
    try:
        with open(json_path, encoding='utf-8') as source:
            meta = json.load(source).get('meta', {})
    except (OSError, ValueError, AttributeError):
        return ''
    return str(meta.get('target') or meta.get('scan_root') or '')


def _symbols(value) -> List[str]:
    text = str(value).strip()
    parts = []
    start = depth = 0
    for index, char in enumerate(text):
        if char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        elif depth == 0 and char in ',，;；/、\n\r':
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    symbols = []
    for part in parts:
        function = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", part)
        if function:
            symbols.append(function.group(1))
        else:
            tokens = part.split()
            if all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) for token in tokens):
                symbols.extend(tokens)
    return list(dict.fromkeys(symbols))


class CCACompat:
    """Keep compatibility, usage fields and source locations."""

    def __init__(self, hidden: bool = False) -> None:
        self._mapping: Dict[str, List[CCAEntry]] = {}
        self._codes: Dict[str, int] = {}
        self.hidden = hidden

    @property
    def symbols(self) -> Set[str]:
        return set(self._mapping)

    def lookup(self, symbol: str) -> List[CCAEntry]:
        return list(self._mapping.get(symbol, []))

    def load(self, path) -> int:
        def invalid(message):
            raise ValueError(f'Invalid CCA JSON {path}: {message}')

        try:
            with open(path, encoding='utf-8-sig') as source:
                data = json.load(source)
        except ValueError as exc:
            invalid(str(exc))

        if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
                or data['schema_version'] != 1):
            invalid('schema_version must be 1')
        if not isinstance(data.get('conclusions'), list):
            invalid('conclusions must be a list')
        if not isinstance(data.get('interfaces'), list):
            invalid('interfaces must be a list')

        mapping: Dict[str, List[CCAEntry]] = {}
        codes: Dict[str, int] = {}
        used_codes = set()
        for index, item in enumerate(data['conclusions']):
            if not isinstance(item, dict):
                invalid(f'conclusions[{index}] must be an object')
            code, text = item.get('code'), item.get('text')
            if type(code) is not int or code < 1 or code in used_codes:
                invalid(f'conclusions[{index}].code must be a unique positive integer')
            if not isinstance(text, str) or not text.strip() or text in codes:
                invalid(f'conclusions[{index}].text must be unique nonempty text')
            codes[text] = code
            used_codes.add(code)

        for index, item in enumerate(data['interfaces']):
            if not isinstance(item, dict):
                invalid(f'interfaces[{index}] must be an object')
            symbol = item.get('symbol')
            if not isinstance(symbol, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol):
                invalid(f'interfaces[{index}].symbol must be an API name')
            for name in ('compatibility', 'scenarios'):
                if name not in item or (item[name] is not None and not isinstance(item[name], str)):
                    invalid(f'interfaces[{index}].{name} must be text or null')
            description = item.get('difference_description')
            if description is not None and not isinstance(description, str):
                invalid(f'interfaces[{index}].difference_description must be text or null')
            conclusion = item['compatibility']
            if conclusion is not None and conclusion not in codes:
                invalid(f'interfaces[{index}].compatibility has no conclusion code')
            sheet, row = item.get('sheet'), item.get('row')
            if not isinstance(sheet, str) or not sheet.strip() or type(row) is not int or row < 1:
                invalid(f'interfaces[{index}] must have a source sheet and positive row')
            mapping.setdefault(symbol, []).append(CCAEntry(
                symbol, conclusion, sheet, row, item['scenarios'], description))

        self._mapping = mapping
        self._codes = dict(sorted(codes.items(), key=lambda item: item[1]))
        logger.info("Loaded %d CCA interfaces from %s", len(mapping), path)
        return len(mapping)

    def export_codes(self, report_path) -> str:
        path = codebook_path(report_path)
        with open(path, 'w', encoding='utf-8', newline='') as output:
            writer = csv.writer(output, delimiter='\t', lineterminator='\n')
            writer.writerow(['Code', 'Conclusion'])
            for conclusion, code in self._codes.items():
                writer.writerow([code, conclusion])
        logger.info("CCA codebook saved to: %s", path)
        return path

    def conclusion_value(self, symbol: str):
        conclusions = list(dict.fromkeys(
            entry.conclusion for entry in self.lookup(symbol)
            if entry.conclusion is not None
        ))
        if not conclusions:
            return None
        values = (
            [self._codes[value] for value in conclusions]
            if self.hidden else conclusions
        )
        if len(values) == 1:
            return values[0]
        return '\n'.join(str(value) for value in values)

    def write_summary_column(self, ws) -> None:
        from openpyxl.styles import Alignment, Font, PatternFill

        headers = [_header(cell.value) for cell in ws[1]]
        symbol_column = next((
            index for index, header in enumerate(headers, 1)
            if header in _SYMBOL_HEADERS or header == 'symbol'
        ), None)
        if symbol_column is None:
            return
        category_column = next((
            index for index, header in enumerate(headers, 1)
            if header in {'category', '分类', '类别', '接口分类'}
        ), None)
        conclusion_column = next((
            index for index, header in enumerate(headers, 1)
            if header == 'ccacompatibility'
        ), len(headers) + 1)
        cell = ws.cell(1, conclusion_column, 'CCA Compatibility')
        cell.font = Font(bold=True)
        cell.fill = PatternFill('solid', fgColor='E8F4FC')
        ws.column_dimensions[cell.column_letter].width = 60
        for row in range(2, ws.max_row + 1):
            symbol = ws.cell(row, symbol_column).value
            category = (
                ws.cell(row, category_column).value
                if category_column is not None else None
            )
            value = None
            if symbol and not is_custom_category(category):
                value = self.conclusion_value(str(symbol))
            target = ws.cell(row, conclusion_column, value)
            if isinstance(value, str):
                target.data_type = 's'
                target.alignment = Alignment(wrap_text=True, vertical='top')

    def write_scan_conclusion(self, wb, call_sites) -> None:
        from openpyxl.styles import Alignment, Font, PatternFill

        if SCAN_CONCLUSION_SHEET_NAME in wb.sheetnames:
            del wb[SCAN_CONCLUSION_SHEET_NAME]
        ws = wb.create_sheet(SCAN_CONCLUSION_SHEET_NAME)
        headers = ('Area', 'Required Action', 'Call Count', 'Unique API Count')
        ws.append(headers)
        for cell, width in zip(ws[1], (22, 56, 14, 18)):
            cell.font = Font(bold=True)
            cell.fill = PatternFill('solid', fgColor='E8F4FC')
            ws.column_dimensions[cell.column_letter].width = width

        calls = list(call_sites)

        def needs_cca_adaptation(symbol):
            conclusions = {
                entry.conclusion for entry in self.lookup(symbol)
                if entry.conclusion is not None
            }
            return bool(conclusions) and any(
                value != CCA_NO_IMPACT_CONCLUSION for value in conclusions
            )

        sections = (
            (
                'CCA Adaptation',
                '非完全兼容接口数',
                lambda symbol, category: needs_cca_adaptation(symbol),
            ),
            (
                'OCSP', '评估并适配 OCSP 接口',
                lambda symbol, category: symbol.startswith('OCSP_'),
            ),
            (
                'ASYNC', '评估并适配异步接口',
                lambda symbol, category: symbol.startswith('ASYNC_'),
            ),
            (
                'ENGINE', '迁移 ENGINE 接口',
                lambda symbol, category: symbol.startswith('ENGINE_'),
            ),
            (
                'Provider Loading', '仅检查显式加载的 Provider',
                lambda symbol, category: symbol in PROVIDER_LOAD_APIS,
            ),
        )
        for area, action, predicate in sections:
            matched = [
                symbol for symbol, category in calls
                if not is_custom_category(category)
                and predicate(symbol, category)
            ]
            apis = sorted(set(matched))
            ws.append([area, action, len(matched), len(apis)])
            ws.cell(ws.max_row, 2).alignment = Alignment(
                wrap_text=True, vertical='top',
            )
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions

    def write_sheet(self, wb, symbols, excluded_symbols=(),
                    products_by_symbol=None) -> None:
        from openpyxl.styles import Alignment, Font, PatternFill

        for title in _CCA_SHEET_NAMES:
            if title in wb.sheetnames:
                del wb[title]
        ws = wb.create_sheet(CCA_SHEET_NAME)
        ws.append(["OpenSSL API", "CCA Compatibility", "Products",
                   "Difference Description"])
        for cell, width in zip(ws[1], (40, 60, 60, 70)):
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="E8F4FC")
            ws.column_dimensions[cell.column_letter].width = width
        row_index = 2
        for symbol in sorted(set(symbols) - set(excluded_symbols)):
            products = sorted(set((products_by_symbol or {}).get(symbol, ())))
            product = '\n'.join(path for path in products if path) or None
            entries = self.lookup(symbol)
            if not entries:
                ws.append([
                    symbol, CCA_NO_ANALYSIS_CONCLUSION, product, None,
                ])
                if product:
                    ws.cell(row_index, 3).alignment = Alignment(
                        wrap_text=True, vertical="top",
                    )
                row_index += 1
                continue
            for entry in entries:
                conclusion = entry.conclusion or CCA_NO_ANALYSIS_CONCLUSION
                if self.hidden and entry.conclusion is not None:
                    conclusion = self._codes[conclusion]
                ws.append([symbol, conclusion, product,
                           entry.difference_description])
                for column in (2, 3, 4):
                    cell = ws.cell(row_index, column)
                    if isinstance(cell.value, str):
                        cell.data_type = "s"
                    cell.alignment = Alignment(wrap_text=True, vertical="top")
                row_index += 1
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions


def annotate_workbook(input_path, output_path, compat: CCACompat) -> int:
    """Append conclusions for interfaces found in an existing workbook."""
    from . import _vendor  # noqa: F401
    from openpyxl import load_workbook

    if os.path.splitext(str(input_path))[1].lower() != '.xlsx':
        raise ValueError('Input report must be an XLSX workbook')
    if os.path.splitext(str(output_path))[1].lower() != '.xlsx':
        raise ValueError('Output report must be an XLSX workbook')
    with open(input_path, 'rb') as source:
        wb = load_workbook(source)
    try:
        symbols: Set[str] = set()
        excluded_symbols: Set[str] = set()
        observed_call_sites = []
        for ws in wb.worksheets:
            if ws.title in _CCA_SHEET_NAMES:
                continue
            column = None
            category_column = None
            is_call_site_table = False
            for row in ws.iter_rows(values_only=True):
                headers = [_header(value) for value in row]
                found = next((i for i, h in enumerate(headers)
                              if h in _SYMBOL_HEADERS or h == 'symbol'), None)
                if found is not None:
                    column = found
                    category_column = next((i for i, h in enumerate(headers)
                                            if h in {'category', '分类', '类别', '接口分类'}), None)
                    is_call_site_table = 'filepath' in headers
                    continue
                if column is not None and column < len(row) and row[column] is not None:
                    row_symbols = _symbols(row[column])
                    symbols.update(row_symbols)
                    category = (
                        row[category_column]
                        if category_column is not None
                        and category_column < len(row) else None
                    )
                    if is_custom_category(category):
                        excluded_symbols.update(row_symbols)
                    if is_call_site_table:
                        observed_call_sites.extend(
                            (symbol, category) for symbol in row_symbols
                        )
        if not symbols:
            raise ValueError('未找到 OpenSSL 接口列中的接口')
        if 'Symbol Summary' in wb.sheetnames:
            compat.write_summary_column(wb['Symbol Summary'])
        if observed_call_sites:
            compat.write_scan_conclusion(wb, observed_call_sites)
        target = _report_scan_target(input_path)
        products_by_symbol = {
            symbol: {target} for symbol in symbols if target
        }
        compat.write_sheet(
            wb, symbols, excluded_symbols=excluded_symbols,
            products_by_symbol=products_by_symbol,
        )
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        wb.save(output_path)
        compat.export_codes(output_path)
        return len(symbols - excluded_symbols)
    finally:
        wb.close()
