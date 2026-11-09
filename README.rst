| |pypi_downloads| |codecov| |windows| |linux| |mac| |bsd|

ttyscan
=======

*ttyscan* queries a terminal emulator for its type, size and capabilities, creates a
curses-compatible `terminfo(5)`_ entry when needed, and exports corrected ``TERM``, ``COLORTERM``,
``LINES``, ``COLUMNS``, and optionally ``TERMCAP`` values.

Problem
-------

ncurses_ has no XTGETTCAP support, so `terminfo(5)`_ entries for some terminals must be deployed to
remote systems by hand. Until then, curses programs fail to start::

       $ tmux attach
       missing or unsuitable terminal: xterm-kitty

       $ htop
       Error opening terminal: xterm-kitty.

       $ python -c 'import curses;curses.setupterm()'
       Traceback (most recent call last):
         File "<string>", line 1, in <module>
       _curses.error: setupterm: could not find terminal

Solution
--------

*ttyscan* builds the missing `terminfo(5)`_ entry from the ``XTGETTCAP`` (``DCS +q``) query
protocol and exports ``TERMINFO`` so that `setupterm(3)`_ succeeds::

       $ ttyscan -vft
       ttyscan: XTGETTCAP supported, terminal: rio; received 198 caps (11 bool, 5 num, 178 str) in 4ms
       ttyscan: writing /home/jq/.config/ttyscan/terminfo/r/rio
       export COLORTERM=truecolor
       export TERM=rio
       export LINES=28
       export COLUMNS=100
       export TERMINFO=/home/jq/.config/ttyscan/terminfo
       export TERMCAP='rio|XTGETTCAP-discovered terminal::am::ut::hs::km::5i::mi::ms::NP::xn::Co#256::...'

       $ eval `ttyscan`

       $ file -b $TERMINFO/r/rio
       Compiled terminfo entry "rio"

       $ python -c 'import curses;curses.setupterm()'; echo $?
       0

The ``TERMCAP`` value above is abbreviated; *ttyscan* emits all 198 capabilities.

CLI Arguments
-------------

::

    usage: ttyscan [-h] [-v] [-f] [-t] [--version]

    Export terminal capabilities discovered via XTGETTCAP

    options:
      -h, --help     show this help message and exit
      -v, --verbose  Print diagnostic information to stderr
      -f, --force    Force export of all values even if unchanged
      -t, --termcap  Also export TERMCAP value
      --version      show program's version number and exit

*ttyscan* saves a `terminfo(5)`_ file to $XDG_CONFIG_HOME/ttyscan/terminfo or
~/.config/ttyscan/terminfo, and reuses it on later executions unless ``--force`` is given. A run
takes under 200ms.

Installation
------------

.. code-block:: shell

   pip install ttyscan

*ttyscan* requires Python3.6+.

ttyscan.py_ is a stand-alone file: copy it from source and run it directly, for example
``python ~/bin/ttyscan.py``.

Motive
------

Copying ``$HOME/.terminfo`` to the remote machine is the best solution. Enterprise systems, bastion
hosts, cloud consoles, hypervisors, radio, and serial ports make that transfer difficult, and the
usual workaround of exporting ``TERM=xterm`` loses keyboard and screen features or corrupts output.

*ttyscan* demonstrates that a full terminal capability database transfers over XTGETTCAP_. My hope
is that ncurses_ and `setupterm(3)`_ negotiate it directly one day, and this tool retires.

Scope
-----

At time of this writing (November 2026), the ucs-detect_ dataset of 42 terminals falls into these
``XTGETTCAP`` categories:

- **Full**: AbsoluteTelnet/SSH, Bobcat, contour_, foot_, ghostty_, iTerm2, kitty_, rio_, WezTerm_,
  and XTerm.NET report screen, numeric, and string capabilities sufficient to build a terminfo
  entry. *ttyscan* produces terminfo files for these, and may also discover ``TERM`` from ``TN``
  and ``COLORTERM=truecolor`` from ``RGB``.

- **Partial**: GNOME Terminal, mlterm, TeraTerm, Terminator, XFCE Terminal, and XTerm_ report
  ``TN``, ``Co``, ``RGB``, and a handful of keyboard sequences. *ttyscan* exports ``TERM`` from
  ``TN`` and ``COLORTERM`` from ``RGB``, and builds no terminfo entry. With XTerm_, try the
  ubiquitous ``TERM=xterm-256color``.

- **No Support**: alacritty (refuses: `alacritty/vte#98`_), Extraterm, Hyper, Konsole (requested:
  `KDE#507017`_), libvterm, linux fbdev, mintty, pterm, QTerminal, rxvt-unicode, screen, securecrt,
  st, SyncTERM, Tabby, Terminal.exe (planned: `microsoft/terminal#17735`_), terminology, tmux
  (passthrough: `tmux/tmux#3755`_), VS Code (xterm.js, proposal: `xtermjs/xterm.js#4107`_), Warp,
  weston-terminal, Zellij, and zutty.

- **Non-Compliant**: ConEmu, cool-retro-term, and Apple Terminal print raw query text such as
  ``+q544e+q524742+q636f6c6f7273`` on screen, where the specification asks for silent consumption
  of VT100 Mode DCS queries. QTerminal (`fixed upstream
  <https://github.com/lxqt/qtermwidget/pull/644>`_) and PuTTY now ignore the query.

Architecture
------------

- ``XTGETTCAP`` field ``TN`` corrects ``TERM``.
- ``XTGETTCAP`` field ``RGB`` corrects ``COLORTERM``.
- ``XTGETTCAP`` supplies all available keyboard and screen capability strings.
- DEC Private Mode 2048 (In-Band Resize) reports the window size; the Cursor Position Report
  sequence from XTerm's `resize.c <https://github.com/joejulian/xterm/blob/master/resize.c>`_
  serves as the fallback.
- DECRQSS_ (Request Setting Selection) probes truecolor support by setting and querying a 24-bit
  background color when ``RGB`` is unavailable.

Terminal identification
-----------------------

When ``TERM_PROGRAM`` is unset or ``--force`` is given, *ttyscan* asks the terminal to name itself,
trying three methods in order. Identification writes ``TERM_PROGRAM`` and
``TERM_PROGRAM_VERSION``; ``TERM`` comes from ``TN``.

XTVERSION (``CSI > q``) answers with ``DCS > | name version ST``.

When XTVERSION is silent, ``ENQ`` (``0x05``) returns the printable answerback, for example
``Extraterm 0.81.4``, whose trailing token holding a digit becomes ``TERM_PROGRAM_VERSION``.
urxvt's default answerback is its DA response, ``ESC [ ? 1 ; 2 c``, which *ttyscan* maps to urxvt.
Some terminals answer past the CPR fence, so *ttyscan* reads a further 50ms.

When ENQ is silent, *ttyscan* measures. DA1 (``CSI c``) reports a service class and a set of
extension numbers such as ``CSI ? 62 ; 4 ; 9 ; 22 c``; the extensions are unordered, so the table
compares them as a set. For terminals sharing that DA1, *ttyscan* draws grapheme clusters whose
column widths differ between terminals, narrowing candidates until one remains. Only an exact
match against the embedded table is exported, and an ambiguous measurement exports nothing. A
terminal that normally identifies itself another way joins the table only when a probe separates
it from every measured terminal sharing its DA1.

The table and probes are embedded in ttyscan.py_, generated from ucs-detect_'s collected width
data by ``tox -e update``.

Details
-------

``XTGETTCAP`` support varies by terminal. foot_ describes the protocol best: XTerm_ queries
keyboard keys plus three custom capabilities, ``TN`` (terminal name), ``Co`` (number of colors),
and ``RGB`` (bits per color channel, with different semantics from the file-based ``RGB``
capability). Kitty queries all integer and string capabilities, and foot adds boolean capabilities
for a complete terminfo over the wire.

All of ``TERM``, ``COLORTERM``, ``LINES``, and ``COLUMNS`` go missing across some transports:

- ssh forwards ``COLORTERM`` only with ``SendEnv`` in `ssh_config(5)`_ and ``AcceptEnv`` in
  `sshd_config(5)`_.
- serial forwards none; the host `agetty(8)`_ configuration defines ``TERM``.
- rlogin forwards all but ``COLORTERM``.
- telnet forwards all, with IAC NAWS and NEW-ENVIRON support varying by software.
- websocket forwards none without customization, common for in-browser terminals.

*ttyscan* re-exports a corrected value whenever one is unset or differs.

Every query ends with a Cursor Position Report (CPR) that tests for a negative response, so the
timeout elapses for terminal automation such as tcl/expect pexpect. Set the timeout with
``TTYSCAN_QUERY_TIMEOUT=10.0`` (float, seconds).

.. _`agetty(8)`: https://linux.die.net/man/8/agetty
.. _`alacritty/vte#98`: https://github.com/alacritty/vte/issues/98
.. _contour: https://github.com/contour-terminal/contour
.. _DECRQSS: https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h4-Device-Control-functions:DCS-plus-q-Pt-ST.F95
.. _foot: https://codeberg.org/dnkl/foot#xtgettcap
.. _ghostty: https://mitchellh.com/writing/ghostty-devlog-004
.. _`KDE#507017`: https://bugs.kde.org/show_bug.cgi?id=507017
.. _kitty: https://sw.kovidgoyal.net/kitty/kittens/query_terminal/
.. _`microsoft/terminal#17735`: https://github.com/microsoft/terminal/issues/17735
.. _ncurses: https://invisible-island.net/ncurses/
.. _rio: https://rioterm.com/changelog#0220
.. _`setupterm(3)`: https://linux.die.net/man/3/setupterm
.. _`ssh_config(5)`: https://linux.die.net/man/5/ssh_config
.. _`sshd_config(5)`: https://linux.die.net/man/5/sshd_config
.. _`terminfo(5)`: https://linux.die.net/man/5/terminfo
.. _`tmux/tmux#3755`: https://github.com/tmux/tmux/issues/3755
.. _`ttyscan.py`: https://github.com/jquast/ttyscan/blob/master/ttyscan.py
.. _ucs-detect: https://ucs-detect.readthedocs.io/results.html#terminal-capabilities
.. _wezterm: https://wezterm.org/
.. _XTerm: https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h4-Device-Control-functions:DCS-plus-q-Pt-ST.F95
.. _`xtermjs/xterm.js#4107`: https://github.com/xtermjs/xterm.js/issues/4107
.. _XTGETTCAP: https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h4-Device-Control-functions:DCS-plus-q-Pt-ST.F95
.. |pypi_downloads| image:: https://img.shields.io/pypi/dm/ttyscan.svg?logo=pypi
    :alt: Downloads
    :target: https://pypi.org/project/ttyscan/
.. |codecov| image:: https://codecov.io/gh/jquast/ttyscan/branch/master/graph/badge.svg
    :alt: codecov.io Code Coverage
    :target: https://codecov.io/gh/jquast/ttyscan/
.. |linux| image:: https://img.shields.io/badge/Linux-yes-success?logo=linux
    :alt: Linux supported
.. |windows| image:: https://img.shields.io/badge/Windows-yes-success?logo=windows
    :alt: Windows supported
.. |mac| image:: https://img.shields.io/badge/MacOS-yes-success?logo=apple
    :alt: MacOS supported
.. |bsd| image:: https://img.shields.io/badge/BSD-yes-success?logo=freebsd
    :alt: BSD supported
