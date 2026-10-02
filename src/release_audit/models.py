from dataclasses import dataclass
from enum import Enum


class EntryType(Enum):
    SOURCE = "SOURCE"
    VERIFICATION = "VERIFICATION"
    EVIDENCE = "EVIDENCE"


class Scope(Enum):
    CANONICAL = "canonical"
    NONCANONICAL = "noncanonical"


@dataclass
class ManifestEntry:
    entry_type: EntryType
    file_path: str
    expected_hash: str

    @property
    def scope(self) -> Scope:
        if self.entry_type in (EntryType.SOURCE, EntryType.VERIFICATION):
            return Scope.CANONICAL

        return Scope.NONCANONICAL