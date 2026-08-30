"""Tests for loading FPP topology analysis data."""

from fprime_python_model.semantics.types_values import FloatKind, FloatType, IntegerType
from fprime_python_model.semantics.types_values import PrimitiveIntKind, PrimitiveIntType

from fprime_topology_analysis.topology_graph import _AnalysisTranslator


def test_analysis_translator_supports_numeric_type_tags():
    translator = object.__new__(_AnalysisTranslator)

    integer = translator.translate_type({"PrimitiveInt": {"kind": {"U32": {}}}})
    arbitrary_integer = translator.translate_type({"Integer": {}})
    floating_point = translator.translate_type({"Float": {"kind": {"F32": {}}}})

    assert integer == PrimitiveIntType(PrimitiveIntKind.U32)
    assert arbitrary_integer == IntegerType()
    assert floating_point == FloatType(FloatKind.F32)
