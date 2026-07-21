from titan_decoder.optional_formats import (
    OPTIONAL_FORMAT_MODULES,
    optional_format_availability,
    optional_format_status,
)


def test_optional_format_availability_imports_every_declared_module():
    imported = []

    def importer(name):
        imported.append(name)
        if name == "cabarchive":
            raise ImportError("missing")
        return object()

    availability = optional_format_availability(importer)

    assert tuple(imported) == OPTIONAL_FORMAT_MODULES
    assert availability["brotli"] is True
    assert availability["cabarchive"] is False


def test_optional_format_status_explains_degraded_readiness():
    def importer(name):
        if name in {"rarfile", "pycdlib"}:
            raise RuntimeError("broken native dependency")
        return object()

    status = optional_format_status(importer)

    assert status["ready"] is False
    assert status["missing"] == ["pycdlib", "rarfile"]
    assert "titan-decoder[formats]" in status["install_hint"]
