"""
Unit tests — app/services/benchmark_service._metrics()

Validates precision, recall, F1, and FP-rate calculations across
perfect, zero, edge, and mixed TP/FP/FN/TN combinations.
"""
import pytest
from app.services.benchmark_service import _metrics


class TestMetricsPerfectDetection:
    def test_all_true_positives(self):
        p, r, f1, fpr = _metrics(tp=10, fp=0, fn=0, tn=0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0
        assert fpr == 0.0

    def test_all_true_negatives(self):
        p, r, f1, fpr = _metrics(tp=0, fp=0, fn=0, tn=10)
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0
        assert fpr == 0.0


class TestMetricsZeroCases:
    def test_all_zeros_returns_zeros(self):
        p, r, f1, fpr = _metrics(0, 0, 0, 0)
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0
        assert fpr == 0.0

    def test_zero_tp_zero_fp_no_division_error(self):
        p, r, f1, fpr = _metrics(tp=0, fp=0, fn=5, tn=5)
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0

    def test_zero_fp_zero_tn_no_division_error(self):
        p, r, f1, fpr = _metrics(tp=5, fp=0, fn=0, tn=0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0
        assert fpr == 0.0


class TestMetricsMixedValues:
    def test_standard_benchmark_scenario(self):
        # 80 TP, 10 FP, 20 FN, 90 TN
        p, r, f1, fpr = _metrics(80, 10, 20, 90)
        assert p == pytest.approx(80 / 90, abs=1e-4)
        assert r == pytest.approx(80 / 100, abs=1e-4)
        expected_f1 = 2 * p * r / (p + r)
        assert f1 == pytest.approx(expected_f1, abs=1e-4)
        assert fpr == pytest.approx(10 / 100, abs=1e-4)

    def test_high_fp_rate_scenario(self):
        p, r, f1, fpr = _metrics(tp=5, fp=45, fn=5, tn=5)
        assert p == pytest.approx(5 / 50, abs=1e-4)
        assert fpr == pytest.approx(45 / 50, abs=1e-4)

    def test_high_fn_low_recall(self):
        p, r, f1, fpr = _metrics(tp=10, fp=0, fn=90, tn=0)
        assert p == 1.0
        assert r == pytest.approx(10 / 100, abs=1e-4)
        assert f1 < 0.2

    def test_equal_tp_fp_fn(self):
        p, r, f1, fpr = _metrics(tp=10, fp=10, fn=10, tn=10)
        assert p == pytest.approx(0.5, abs=1e-4)
        assert r == pytest.approx(0.5, abs=1e-4)
        assert f1 == pytest.approx(0.5, abs=1e-4)
        assert fpr == pytest.approx(0.5, abs=1e-4)


class TestMetricsRounding:
    def test_values_rounded_to_4_decimal_places(self):
        p, r, f1, fpr = _metrics(tp=1, fp=3, fn=2, tn=7)
        # Check none exceed 4 decimal places
        for v in (p, r, f1, fpr):
            assert v == round(v, 4)

    def test_returns_four_values(self):
        result = _metrics(10, 5, 5, 80)
        assert len(result) == 4

    def test_all_values_between_zero_and_one(self):
        p, r, f1, fpr = _metrics(50, 10, 20, 120)
        for v in (p, r, f1, fpr):
            assert 0.0 <= v <= 1.0


class TestMetricsF1Properties:
    def test_f1_is_harmonic_mean_of_precision_recall(self):
        p, r, f1, _ = _metrics(tp=8, fp=2, fn=4, tn=10)
        expected = 2 * p * r / (p + r) if (p + r) else 0.0
        assert f1 == pytest.approx(round(expected, 4), abs=1e-6)

    def test_f1_zero_when_no_true_positives(self):
        _, _, f1, _ = _metrics(tp=0, fp=5, fn=5, tn=10)
        assert f1 == 0.0

    def test_f1_bounded_by_precision_and_recall(self):
        p, r, f1, _ = _metrics(tp=7, fp=3, fn=5, tn=15)
        assert f1 <= max(p, r)
        assert f1 >= min(p, r)
