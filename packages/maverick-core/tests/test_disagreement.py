"""Disagreement entropy."""
from __future__ import annotations

from maverick.disagreement import answer_entropy


class TestAnswerEntropy:
    def test_identical_answers_zero_entropy(self):
        assert answer_entropy(["yes", "yes", "yes"]) == 0.0

    def test_all_unique_max_entropy(self):
        ent = answer_entropy(["a", "b", "c", "d"])
        assert 0.99 < ent <= 1.0

    def test_two_clusters_mid_entropy(self):
        """2-of-yes + 2-of-no out of 4 = log(2)/log(4) = 0.5."""
        ent = answer_entropy(["yes", "yes", "no", "no"])
        assert 0.49 < ent < 0.51

    def test_lopsided_low_entropy(self):
        # 4 of "yes", 1 of "no" → entropy below 0.75.
        ent = answer_entropy(["yes", "yes", "yes", "yes", "no"])
        assert 0.0 < ent < 0.75

    def test_single_answer_zero(self):
        assert answer_entropy(["only"]) == 0.0

    def test_empty_zero(self):
        assert answer_entropy([]) == 0.0

    def test_whitespace_doesnt_count_as_disagreement(self):
        """Same answer with different formatting should NOT be disagreement."""
        ent = answer_entropy(["the answer", "the answer\n\n", "  the answer  "])
        assert ent == 0.0
