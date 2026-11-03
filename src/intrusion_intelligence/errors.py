"""Shared exception types for the application."""


class ProjectError(Exception):
    """Base exception for errors that the application can report clearly."""


class ConfigurationError(ProjectError):
    """Raised when project configuration is missing or invalid."""


class IngestionError(ProjectError):
    """Base exception for dataset ingestion failures."""


class DatasetDirectoryError(IngestionError):
    """Raised when a configured dataset directory is missing or invalid."""


class DatasetDiscoveryError(IngestionError):
    """Raised when no supported dataset files can be discovered."""


class CSVInspectionError(IngestionError):
    """Raised when a CSV file cannot be inspected."""


class SchemaValidationError(IngestionError):
    """Raised when input files are structurally invalid or incompatible."""


class DataLoadingError(IngestionError):
    """Raised when a validated CSV file cannot be loaded."""


class MetadataWriteError(IngestionError):
    """Raised when ingestion metadata or reports cannot be written."""


class EDAAnalysisError(ProjectError):
    """Raised when exploratory analysis cannot run on the selected dataset."""
