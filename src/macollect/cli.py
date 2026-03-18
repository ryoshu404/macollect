import argparse
import importlib.metadata
import os
import sys
from pathlib import Path
from macollect.pipeline import PLACEHOLDER
from macollect.formatters.json_formatter import format_json

try:
    VERSION = importlib.metadata.version('macollect')
except importlib.metadata.PackageNotFoundError:
    VERSION = 'unknown'

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog='macollect',
        description='macollect - modular macOS forensic artifact collector for IR and TH',
        epilog='https://github.com/ryoshu404/macollect',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-m', '--modules', nargs='+', choices=['baseline', 'persistence', 
        'processes', 'signing', 'tcc', 'xattr', 'credentials','logs'], default=None, 
        help='--modules: baseline persistence processes signing tcc xattr credentials logs')
    parser.add_argument('-f', '--format', choices=['json'], default='json', help='Output format')
    parser.add_argument('-t', '--time-window', type=int, default=24, help='Time window for ' \
                        'unified logs')
    parser.add_argument('-o', '--output', type=str, help='Specify output location')
    parser.add_argument('-v', '--version', action='version', version=f'macollect {VERSION}')

def main():

    args = parse_args()
    if os.geteuid() != 0:
        print('macollect requires sudo. Run with: sudo macollect', file=sys.stderr)
        sys.exit(1)
    pipeline = PLACEHOLDER(modules=args.modules, time_window=args.time_window)
    report = pipeline.PLACEHOLDERUN()
    match args.format:
        case 'json':
            formatted = format_json(report)
    if args.output:
        output = Path(args.output).expanduser()
        with open(output, 'w', encoding='utf-8') as f:
            f.write(formatted)
    else:
        print(formatted)

if __name__ == '__main__':
    main()