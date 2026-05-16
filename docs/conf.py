"""Sphinx documentation configuration for ttyscan."""

import datetime
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, os.path.pardir)))

from ttyscan import __version__ as version  # noqa: E402

project = 'ttyscan'
release = version

_start_year = 2026
_current_year = datetime.datetime.now().year
if _start_year == _current_year:
    copyright = f'{_start_year} Jeff Quast'
else:
    copyright = f'{_start_year}-{_current_year} Jeff Quast'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
]

templates_path = ['_templates']
source_suffix = {'.rst': 'restructuredtext'}
master_doc = 'index'
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

add_function_parentheses = True
add_module_names = False
pygments_style = 'native'

html_theme = 'sphinx_rtd_theme'
html_show_sphinx = False
html_show_copyright = True

autodoc_member_order = 'bysource'
autoclass_content = 'both'

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}
