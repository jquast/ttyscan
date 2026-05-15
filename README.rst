| |pypi_downloads| |codecov| |windows| |linux| |mac| |bsd|


**Note: This software is not yet released! It best integrates with the next release of**
**Blessed (1.40), in review: https://github.com/jquast/blessed/pull/375**

ttyscan
=======

*ttyscan* queries a terminal emulator for its type, size and capabilities, creating a
curses-compatible `terminfo(5)`_ file entry if necessary, and exports any corrected values of
``TERM``, ``COLORTERM``, ``LINES``, ``COLUMNS``, and optionally ``TERMCAP`` environment variables.

Problem
-------

ncurses_ does not support XTGETTCAP, and so `terminfo(5)`_ files for some terminals must be
deployed to remote systems by system operators in some circumstances.

Curses programs fail to start until those files are deployed or an alternate ``TERM`` is exported.
All kinds of errors and warnings may be raised until this is done, some examples::

       $ tmux attach
       missing or unsuitable terminal: xterm-kitty

       $ irssi
       setupterm() failed for TERM=xterm-kitty: 0
       Can't initialize screen handling.

       $ htop
       Error opening terminal: xterm-kitty.

       $ python -c 'import curses;curses.setupterm()'
       Traceback (most recent call last):
         File "<string>", line 1, in <module>
       _curses.error: setupterm: could not find terminal

       $ git log -p
       WARNING: terminal is not fully functional
       Press RETURN to continue 

Solution
--------

*ttyscan* creates the missing `terminfo(5)` file using the ``XTGETTCAP`` (``DCS +q``) terminal query
protocol when supported, and suggests a new ``TERMINFO`` environment value for export, allowing
legacy calls to curses of `setupterm(3)`_ to succeed::

       $ ttyscan -vft
       ttyscan: probing terminal via XTGETTCAP ...
       ttyscan: size via dual CPR: 28x100
       ttyscan: XTGETTCAP supported, terminal: rio; received 204 caps (10 bool, 5 num, 185 str) in 1523ms
       ttyscan: writing /home/jq/.config/ttyscan/terminfo/r/rio
       export COLORTERM=truecolor
       export TERM=rio
       export LINES=28
       export COLUMNS=100
       export TERMINFO=/home/jq/.config/ttyscan/terminfo
       export TERMCAP='rio|XTGETTCAP-discovered terminal::am::ut::hs::km::5i::mi::ms::NP::xn::Co#256::co#80::it#8::li#24::pa#32767::ac=``aaffggiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~::bl=^G::mb=\E[5m::md=\E[1m::vi=\E[?25l::cl=\E[H\E[2J::ve=\E[?12l\E[?25h::cr=\r::cs=\E[%i%p1%d;%p2%dr::le=\b::DO=\E[%p1%dB::do=\n::nd=\E[C::cm=\E[%i%p1%d;%p2%dH::up=\E[A::vs=\E[?12;25h::dC=\E[P::mh=\E[2m::dl=\E[M::ds=\E]2;^G::ec=\E[%p1%dX::cd=\E[J::ce=\E[K::cb=\E[1K::vb=\E[?5h$<100/>\E[?5l::fs=^G::ho=\E[H::ch=\E[%i%p1%dG::ta=\t::st=\EH::al=\E[L::sf=\n::mk=\E[8m::is=\E[!p\E[?3;4l\E[4l\E>::K2=\EOE::kb=^?::kB=\E[Z::kl=\EOD::kd=\EOB::kr=\EOC::ku=\EOA::kD=\E[3~::@7=\EOF::@8=\EOM::k1=\EOP::k0=\E[21~::F1=\E[23~::F2=\E[24~::k2=\EOQ::k3=\EOR::k4=\EOS::k5=\E[15~::k6=\E[17~::k7=\E[18~::k8=\E[19~::k9=\E[20~::kh=\EOH::kI=\E[2~::kH=\E[1;2B::kN=\E[6~::kP=\E[5~::op=\E[39;49m::rp=%p1%c\E[%p2%{1}%-%db::mr=\E[7m::sr=\EM::ZR=\E[23m::ae=\E(B::te=\E[?1049l\E[23;0;0t::ei=\E[4l::ke=\E[?1l\E>::se=\E[27m::ue=\E[24m::r1=\Ec\E]104^G::r2=\E[!p\E[?3;4l\E[4l\E>::sa=%?%p9%t\E(0%e\E(B%;\E[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p7%t;8%;m::me=\E(B\E[m::ZH=\E[3m::as=\E(0::ti=\E[?1049h\E[22;0;0t::im=\E[4h::ks=\E[?1h\E=::so=\E[7m::us=\E[4m::ct=\E[3g::ts=\E]2;::cv=\E[%i%p1%dd:' 

       $ eval `ttyscan`

       $ echo $TERM, $TERMINFO
       rio, /home/jquast/.config/ttyscan/terminfo

       $ file -b /home/jquast/.config/ttyscan/terminfo/r/rio
       Compiled terminfo entry "rio"

       $ python -c 'import curses;curses.setupterm()'; echo $?
       0

CLI Arguments
-------------

::

    usage: ttyscan [-h] [-v] [-f] [-t]

    Export terminal capabilities discovered via XTGETTCAP

    options:
      -h, --help     show this help message and exit
      -v, --verbose  Print diagnostic information to stderr
      -f, --force    Force export of all values even if unchanged
      -t, --termcap  Also export TERMCAP value

Installation
------------

.. code-block:: shell

   pip install ttyscan

*ttyscan* requires Python3.8+

Motive
------

Naturally, transferring your ``.terminfo`` folder to a remote machine is the best solution.
Enterprise systems, bastion hosts, cloud systems, web consoles, hypervisors, radio, and serial ports
however can be a challenging place or protocol layer to deploy terminfo files.

Some workarounds include exporting a generally-compatible ``TERM=xterm-256color`` or ``vt220``  with
sometimes minor corruption of screen output or missed interpretation of keyboard input like
backspace or delete or small reduction of features, like italic or underlined text or number of
colors.

And so **this tool is not often needed** except for the very serious terminal connoisseur.  It
serves as a demonstration: that terminal capability strings can be transferred using XTGETTCAP_ for
many modern terminals, and that a `terminfo(5)`_ and `termcap(5)`_ files and environment values may
be automatically configured.  It is hoped that this utility is not commonly used or required, and
that `setupterm(3)`_ may negotiate for ``XTGETTCAP`` at some point in the future.

Scope
-----

At time of this writing (May 2026), the ucs-detect_ dataset of 42 terminals shows three categories
of support for ``XTGETTCAP``:

- **Full** ``XTGETTCAP`` capability support: contour_, foot_, ghostty_, kitty_, rio, and wezterm
  transmit their complete terminfo boolean, numeric, and string capabilities via XTGETTCAP_.

  *ttyscan* produces terminfo files for only these terminals.  *ttyscan* may discover preferred
  ``TERM`` from ``TN``, and ``COLORTERM=truecolor`` from ``RGB``.

- **Partial** ``XTGETTCAP`` capability support: XTerm_, iterm2, mlterm, AbsoluteTelnet/SSH, GNOME
  Terminal, LXTerminal, terminator, termit, and xfce4-terminal report only ``TN``, ``Co``, and
  ``RGB``. XTerm_ supports keyboard input sequences but does not transmit the other capabilities
  required to rebuild a complete terminal capability description.

  *ttyscan* may discover preferred ``TERM`` from ``TN``, and ``COLORTERM=truecolor`` from ``RGB``.

- **None**: alacritty (refuses: `alacritty/vte#98`_, tracked: `alacritty/alacritty#7268`_), bobcat,
  cmd.exe, ConEmu, cool-retro-term, Extraterm, Hyper, Konsole (requested: `KDE#507017`_), linux
  fbdev, mintty, PuTTY, QTerminal, rxvt-unicode, screen, securecrt, st, Tabby, Apple Terminal,
  Terminal.exe (planned: `microsoft/terminal#17735`_), terminology, tmux (passthrough:
  `tmux/tmux#3755`_), libvterm, VS Code (xterm.js, proposal: `xtermjs/xterm.js#4107`_),
  weston-terminal, and zutty.

Architecture
------------

An easy-to-deploy variant of this program would be better created as **one single standalone**
python script, without any 3rd party requirements or support for windows. This may be done in the
future if it appears useful enough.

*ttyscan* currently carries some unnecessary dependencies: only a very small subset of blessed_ and
jinxed_ are used, and wcwidth_ isn't even used at all!  These "middle-weight" dependencies are used
to reduce the size and complexity of this demonstration code.

*ttyscan* uses the following,

- ``TN`` is used to correct ``TERM`` when unmatched.
- ``RGB`` is used to correct ``COLORTERM`` when unmatched.
- all capability strings, keyboard and screen, when provided by ``XTGETTCAP``.
- DEC Private Mode 2048 (In-Band Resize) to determine the window size
- Or failing that, Cursor Position Report like XTerm's `resize.c
  <https://github.com/joejulian/xterm/blob/master/resize.c>`_
- blessed_ library for all Terminal interaction and capability detection

Details
-------

The use of ``XTGETTCAP`` is best described by foot_:

  ``XTGETTCAP`` is an escape sequence initially introduced by XTerm_, and also implemented (and extended,
  to some degree) by Kitty.
 
  Applications using this feature do not need to use the classic, file-based, terminfo definition.
 
  XTerm's implementation (as of XTerm-370) only supports querying key (as in keyboard keys)
  capabilities, and three custom capabilities:
  
  ``TN`` - terminal name
  ``Co`` - number of colors (alias for the colors capability)
  ``RGB`` - number of bits per color channel (different semantics from the RGB capability in file-based
  terminfo definitions!).
 
  Kitty has extended this, and also supports querying all integer and string capabilities.
 
  Foot supports this, and extends it even further, to also include boolean capabilities.
  **This means foot's entire terminfo can be queried via ``XTGETTCAP``.**

Further, all of ``TERM``, ``COLORTERM``, ``LINES``, or ``COLUMNS`` may not be transmitted by all
software or protocols, some examples:

- ssh does not forward ``COLORTERM`` unless configured using ``SendEnv`` in `ssh_config(5)`_ and
  ``AcceptEnv`` in `sshd_config(5)`_.
- serial does not forward any; ``TERM`` is defined by host `agetty(8)`_ configuration, for example.
- rlogin can forward all but ``COLORTERM``.
- telnet can forward all, but IAC NAWS and NEW-ENVIRON capability varies by software.
- websocket cannot forward any without customization, often used in-browser.

*ttyscan* detects when these variables are unset or do not match values and re-exports the corrected
values when they differ.

.. _kitty: https://sw.kovidgoyal.net/kitty/kittens/query_terminal/
.. _ghostty: https://mitchellh.com/writing/ghostty-devlog-004
.. _alacritty: https://github.com/alacritty/vte/issues/98
.. _`alacritty/vte#98`: https://github.com/alacritty/vte/issues/98
.. _ucs-detect: https://github.com/jquast/ucs-detect
.. _`agetty(8)`: https://linux.die.net/man/8/agetty
.. _blessed: https://pypi.org/project/blessed/
.. _foot: https://codeberg.org/dnkl/foot#xtgettcap
.. _ncurses: https://invisible-island.net/ncurses/
.. _`setupterm(3)`: https://linux.die.net/man/3/setupterm
.. _`ssh_config(5)`: https://linux.die.net/man/5/ssh_config
.. _`sshd_config(5)`: https://linux.die.net/man/5/sshd_config
.. _`terminfo(5)`: https://linux.die.net/man/5/terminfo
.. _XTGETTCAP specification: https://gitlab.freedesktop.org/terminal-wg/specifications/-/merge_requests/7
.. _`xtermjs/xterm.js#4107`: https://github.com/xtermjs/xterm.js/issues/4107
.. _`microsoft/terminal#17735`: https://github.com/microsoft/terminal/issues/17735
.. _`KDE#507017`: https://bugs.kde.org/show_bug.cgi?id=507017
.. _`tmux/tmux#3755`: https://github.com/tmux/tmux/issues/3755
.. _`alacritty/alacritty#7268`: https://github.com/alacritty/alacritty/issues/7268

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
