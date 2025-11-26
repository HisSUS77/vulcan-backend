from enum import Enum


class PatchStatus(str, Enum):
    GENERATED = "GENERATED"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    EXPORTED = "EXPORTED"
