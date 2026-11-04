"""Model-authored TeX may not reach host files or processes."""
from __future__ import annotations

import pytest


@pytest.mark.parametrize("source", [
    r"\makeatletter\@@input{/etc/passwd}", r"^^5cinput{x}", r"\csname input\endcsname{x}",
    r"\InputIfFileExists{x}{}{}", r"\verbatiminput{x}", r"\lstinputlisting{x}",
    r"\CatchFileDef\x{y}{}", r"\read16 to\x", r"\includegraphics{/etc/passwd}",
    r"\includegraphics{../../x.png}", r"\immediate\openout1=x", r"\write18{ls}"])
def test_tex_that_can_reach_files_or_processes_is_refused(source):
    from maverick.sandbox.document_engine import _tex_reaches_outside
    assert _tex_reaches_outside(source)


def test_ordinary_tex_and_workspace_images_are_allowed():
    from maverick.sandbox.document_engine import _tex_reaches_outside
    assert not _tex_reaches_outside(
        r"\documentclass{article}\begin{document}\section{R} 50\% of $x^2$ "
        r"\includegraphics[width=3cm]{figs/chart.png}\end{document}")
