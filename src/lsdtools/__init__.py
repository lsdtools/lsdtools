"""lsdtools: the LSD SDK's names, and the ``lsdtools`` command that installs and runs LSD.

This is the PyPI front door (``pip install lsdtools``). It holds no engine: the SDK runs inside an exact
signed LSD runtime, the way a Blender script runs inside Blender::

    lsdtools setup                 # once: install the current LSD runtime
    lsdtools python my_script.py   # run a script that imports lsdtools, inside that runtime

Here an SDK name raises ``RuntimeRequiredError`` (an ``ImportError``) that says so; editors still see
every name in ``__all__``. ``lsdtools._manager`` is the command's own code.
"""

__lsdtools_flavor__ = "facade"
__version__ = '1.0.0rc3'
API_VERSION = '1.0'

__all__ = ['API_VERSION', 'ActionInputField', 'ActionInputSchema', 'ChartPayload', 'Chunk', 'Component', 'Configurable', 'Context', 'Creates', 'DomainMode', 'DomainPolicy', 'Engine', 'Entity', 'Events', 'FieldDefinition', 'FieldProducer', 'FileArtifact', 'FileRole', 'FileSetPayload', 'InputArtifact', 'LayerPayload', 'LegendPayload', 'OutputRef', 'PARQUET_WRITE_POLICY_VERSION', 'PackageHost', 'ParquetDataset', 'ParquetScanCancelled', 'ParquetScanOptions', 'ParquetSourceMetadata', 'ParquetWritePolicy', 'ProjectSemanticsCatalog', 'ProjectSemanticsRevisionError', 'Reads', 'RunResult', 'RuntimeRequiredError', 'SchemaError', 'Source', 'StepContext', 'StyleAssignment', 'StyleDefinition', 'SymbologyUse', 'Table', 'ToDisk', 'ToMemory', 'Tool', 'Trip', 'TripView', 'ValidationError', 'VariableConcept', 'View', 'ViewPresentation', 'ViewerPayload', 'Writes', 'action', 'apply_column_map', 'autoselect_largecsv_source', 'columnmap_param', 'describe_api', 'ecs', 'extend', 'generate_step', 'models', 'open_parquet_dataset', 'param', 'parquet_write_policy', 'parse_column_map', 'parse_source', 'profiling', 'publish', 'resolve_column_map', 'server', 'text_completer', 'validators', 'views', 'write_parquet_table']

_SDK = frozenset(__all__) - {"API_VERSION", "RuntimeRequiredError"}


class RuntimeRequiredError(ImportError):
    """An SDK name was used outside an LSD runtime."""


def __getattr__(name):
    if name in _SDK:
        raise RuntimeRequiredError(
            f"lsdtools.{name} runs inside an LSD runtime, not in this Python: run the script with "
            "`lsdtools python your_script.py` (`lsdtools setup` installs the runtime once)", name=name)
    raise AttributeError(f"module 'lsdtools' has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | _SDK)
