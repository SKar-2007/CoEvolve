"""Unit tests for CoEvolve Sandbox core modules."""

from __future__ import annotations

import pytest

from packages.elo.calculator import EloCalculator, Ratings
from packages.elo.difficulty import tier_from_rating_difference, describe_tier, mapping_for


class TestEloCalculator:
    """Test the Elo rating calculator."""

    @pytest.fixture
    def calculator(self):
        return EloCalculator(k_factor=32, initial=1500)

    def test_initial_ratings(self, calculator):
        """New calculator starts with default ratings."""
        assert calculator.initial == 1500

    def test_expected_score(self, calculator):
        """Expected score depends on rating difference."""
        # Equal ratings => 0.5 expected score
        ea, ed = calculator.expected_pair(1500, 1500)
        assert abs(ea - 0.5) < 0.001
        assert ed == 1.0 - ea

    def test_update_attacker_win(self, calculator):
        """Attacker wins => rating goes up, developer goes down."""
        ra, rd = calculator.update_pair(1500, 1500, j=1)  # attacker wins
        assert ra > 1500
        assert rd < 1500

    def test_update_developer_win(self, calculator):
        """Developer wins => rating goes up, attacker goes down."""
        ra, rd = calculator.update_pair(1500, 1500, j=0)  # developer wins
        assert ra < 1500
        assert rd > 1500

    def test_rating_bounds(self, calculator):
        """Ratings stay within configured bounds."""
        for _ in range(100):
            ra, rd = calculator.update_pair(1500, 1500, j=1)
        assert 1000 <= ra <= 2500
        assert 1000 <= rd <= 2500

    def test_k_factor_sensitivity(self):
        """Larger K factor produces larger swings."""
        calc_high = EloCalculator(k_factor=64)
        calc_low = EloCalculator(k_factor=16)
        ra_h, rd_h = calc_high.update_pair(1500, 1500, j=1)
        ra_l, rd_l = calc_low.update_pair(1500, 1500, j=1)
        assert abs(ra_h - 1500) >= abs(ra_l - 1500)


class TestDifficultyMapping:
    """Test difficulty tier mapping from Elo differences."""

    def test_tier_from_difference(self):
        """Negative diff => easier; positive diff => harder."""
        # Negative diff => easier tier
        assert tier_from_rating_difference(-500) == 1
        assert tier_from_rating_difference(-400) == 2
        assert tier_from_rating_difference(-300) == 3
        assert tier_from_rating_difference(-200) == 4
        assert tier_from_rating_difference(-100) == 5

        # Zero diff => intermediate
        assert tier_from_rating_difference(0) == 5

        # Positive diff => harder
        assert tier_from_rating_difference(100) == 6
        assert tier_from_rating_difference(200) == 7
        assert tier_from_rating_difference(300) == 8
        assert tier_from_rating_difference(400) == 9
        assert tier_from_rating_difference(500) == 10

    def test_describe_tier(self):
        """Descriptions match tier numbers."""
        for tier in range(1, 11):
            desc = describe_tier(tier)
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_mapping_for(self):
        """mapping_for returns a DifficultyMapping."""
        mapping = mapping_for(1600, 1500)  # diff = 100 => tier 6
        assert mapping.tier == 6
        assert mapping.rating_difference == 100.0