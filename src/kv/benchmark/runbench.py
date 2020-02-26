import subprocess
import argparse
import os
import random
from collections import OrderedDict
from parse import parse
from bokeh.io import export_png
from bokeh.plotting import figure, output_file, show, save
from bokeh.models import ColumnDataSource, FactorRange
from bokeh.transform import factor_cmap
from bokeh.layouts import gridplot

parser = argparse.ArgumentParser(description='IWKV Benchmarks')
parser.add_argument(
    '-b', '--basedir', help='Base directory with benchmark executables', default='.', nargs='?')
args = parser.parse_args()

basedir = os.path.abspath(args.basedir)
print('Base directory:', basedir)

benchmarks = [
    'iwkv',
    'lmdb',
    'leveldb',
    'kyc',
    'bdb'
]

runs = []

runs += [{'b': 'fillrandom2', 'n': n, 'vz': vz, 'rs': 2853624176, 'sizestats': True}
         for n in (int(1e6),)
         for vz in (1000,)]

runs += [{'b': 'fillrandom2,readrandom,deleterandom', 'n': n, 'vz': vz, 'rs': 2105940112, 'w': ''}
         for n in (int(1e6),)
         for vz in (400,)]

runs += [{'b': 'fillseq,overwrite,deleteseq', 'n': n, 'rs': 570078848, 'w': ''}
         for n in (int(1e6),)
         for vz in (400,)]

runs += [{'b': 'fill100K', 'n': n, 'rs': 1313807505, 'w': ''}
         for n in (int(1e6),)
         for vz in (400,)]

runs += [{'b': 'fillrandom2,readrandom', 'n': n, 'vz': vz, 'rs': 1513135152, 'w': ''}
         for n in (int(10e6),)
         for vz in (200,)]

runs += [{'b': 'readseq,readreverse', 'n': n, 'vz': vz, 'rs': 1553195152, 'w': ''}
         for n in (int(10e6),)
         for vz in (200,)]

runs += [{'b': 'fillrandom2', 'n': n, 'vz': vz, 'rs': 3434783568, 'w': ''}
         for n in (int(10e3),)
         for vz in ((200 * 1024),)]

tests = [
    'fillseq',
    'fillseq2',
    'fillrandom',
    'fillrandom2',
    'overwrite',
    'fillsync',
    'fill100K',
    'deleteseq',
    'deleterandom',
    'readseq',
    'readreverse',
    'readrandom',
    'readmissing',
    'readhot',
    'seekrandom'
]

results = OrderedDict()


def fill_result(bm, run, sizestats, line):
    key = ' '.join(['-{} {}'.format(a, v) for a, v in run.items()])
    if key not in results:
        results[key] = OrderedDict()
    if bm not in results[key]:
        results[key][bm] = OrderedDict()
    res = results[key][bm]

    pval = parse('done: {} in {}', line)
    if sizestats:
        pval = parse('db size: {} ({})', line)
        if pval and 'db size' not in res:
            print(line, flush=True)
            res['db size'] = int(pval[0]) / (1024 * 1024)
    elif pval:
        print(line, flush=True)
        res[pval[0]] = int(pval[1])


def run_benchmark_run(bm, run):
    args = ['{}/{}_benchmark'.format(basedir, bm)]
    sizestats = False
    for a, v in run.items():
        if a in ('sizestats',):
            sizestats = True
            continue
        args.append('-{}'.format(a))
        args.append(str(v))
    print('Run {}'.format(' '.join(args)), flush=True)
    with subprocess.Popen(args,
                          stderr=subprocess.STDOUT,
                          stdout=subprocess.PIPE,
                          universal_newlines=True,
                          cwd=basedir,
                          bufsize=1) as output:
        for line in output.stdout:
            fill_result(bm, run, sizestats, line.strip())
        output.wait()


def run_benchmark(bm):
    for run in runs:
        run_benchmark_run(bm, run)


def run():
    for b in benchmarks:
        run_benchmark(b)


def main():
    run()
    plots = []
    palette = ["#00B377", "#e84d60", "#0054AE", "#c9d9d3",
               "#BFF500", "#555555", "#DFBFFF", "#B1D28F",
               "#FFAA00", "#A18353", "#888888", "#718dbf"]
    for bn, rmap in results.items():
        pfactors = None
        x = [(bm, brun) for bm in iter(rmap) for brun in iter(rmap[bm])]
        if len([v for v in x if v[1] == 'db size']):
            sizestats = True
        else:
            sizestats = False
        if pfactors is None:
            pfactors = [f[1] for f in x]
        counts = [rmap[bm][brun]
                  for bm in iter(rmap) for brun in iter(rmap[bm])]
        source = ColumnDataSource(data=dict(x=x, counts=counts))
        p = figure(x_range=FactorRange(*x), plot_height=350,
                   title=bn)  # y_axis_type="log"
        p.vbar(x='x', top='counts', width=0.9, source=source, line_color='white',
               fill_color=factor_cmap('x', palette=palette, factors=pfactors, start=1, end=2))
        p.y_range.start = 0
        p.yaxis.axis_label = 'Time ms' if not sizestats else 'Database file size (MB)'
        p.x_range.range_padding = 0.1
        p.xaxis.major_label_orientation = 1
        p.xgrid.grid_line_color = None
        # p.toolbar_location = None
        plots.append(p)
        output_file("{}.html".format(bn))
        save(p)
        export_png(p, filename="{}.png".format(bn))

    # grid = gridplot(plots, ncols=1)
    # script, div = components(plots)
    # output_file('runbench.html')
    # save(grid)
    # show(grid)


if __name__ == '__main__':
    main()
