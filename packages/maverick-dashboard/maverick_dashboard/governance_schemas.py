"""Request models for the governance workspace (legal/privacy/compliance)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

_ASSET_ID = r"^MAA-[0-9a-f]{32}$"
_IDENT = r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$"


class GRCSyncRunIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    limit: int = Field(default=50, ge=1, le=200)
    confirm_dispatch: bool

    @model_validator(mode="after")
    def require_dispatch_confirmation(self):
        if self.confirm_dispatch is not True:
            raise ValueError("confirm sending records to the external GRC system")
        return self


class GRCInspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    remote_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{4,128}$")


class GRCResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    note: str = Field(..., min_length=1, max_length=2000)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class FRIAOpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    context: str = Field(..., pattern=_IDENT)


class FRIAElementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    element: str = Field(..., min_length=1, max_length=64)
    content: str = Field(..., min_length=1, max_length=8000)
    expected_revision: int = Field(..., ge=1)


class FRIACompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class FRIAOutdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str = Field(..., min_length=1, max_length=2000)
    expected_revision: int = Field(..., ge=1)


class FRIANotificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    authority: str = Field(..., min_length=1, max_length=512)
    reference: str = Field(..., min_length=1, max_length=512)
    submitted_at: float = Field(..., gt=0)
    expected_revision: int = Field(..., ge=1)


class AnnexIVOpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)


class AnnexIVItemIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    item: str = Field(..., min_length=1, max_length=64)
    reference: str = Field(..., min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class RouteRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    route: str = Field(
        ...,
        pattern=r"^(internal_control_annex_vi|notified_body_annex_vii|sectoral_annex_i)$",
    )
    annex_iii_point: int | None = Field(None, ge=1, le=8)
    harmonised_standards_applied: bool = False
    common_specifications_applied: bool = False
    rationale: str = Field(..., min_length=1, max_length=2000)


class RouteModificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str = Field(..., min_length=1, max_length=2000)
    predetermined: bool = False
    expected_revision: int = Field(..., ge=1)


class PMMPlanIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    plan_reference: str = Field(..., min_length=1, max_length=512)


class PMMReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    outcome: str = Field(..., pattern=r"^(no_change|plan_updated)$")
    plan_reference: str | None = Field(None, min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class RegistrationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    basis: str = Field(
        ...,
        pattern=(
            r"^(provider_high_risk|provider_not_high_risk|"
            r"public_authority_deployer|annex_iii_point_2_national)$"
        ),
    )
    registry: str = Field(..., pattern=r"^(eu_database|national)$")
    reference: str = Field(..., min_length=1, max_length=512)


class IFUOpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)


class GPAIOpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    systemic_risk: bool = False
    open_source_exempt: bool = False


class GPAIObligationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    obligation: str = Field(..., min_length=1, max_length=64)
    reference: str = Field(..., min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class DeployerOpenIn(BaseModel):
    """Open the Art. 26 deployer-obligations register for one system; the
    flags decide which conditional duties (26(4)/(7)/(8)/(9)) apply."""
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_ASSET_ID)
    workplace_use: bool = False
    public_authority: bool = False
    controls_input_data: bool = False
    requires_dpia: bool = False


class DeployerObligationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    obligation: str = Field(..., min_length=1, max_length=64)
    reference: str = Field(..., min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class DeployerOversightIn(BaseModel):
    """Assign Art. 26(2) human oversight to named natural persons."""
    model_config = ConfigDict(extra="forbid", strict=True)

    persons: list[str] = Field(..., min_length=1, max_length=20)
    reference: str = Field(..., min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class FRIAReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    outcome: str = Field(..., pattern=r"^(concur|objections)$")
    notes: str = Field("", max_length=2000)
    expected_revision: int = Field(..., ge=1)


class LiteracyTrainingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key: str = Field(..., pattern=_IDENT)
    title: str = Field(..., min_length=1, max_length=256)
    validity_days: int | None = Field(None, ge=1, le=3650)


class LiteracyRequirementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    role: str = Field(..., pattern=_IDENT)
    trainings: list[LiteracyTrainingIn] = Field(..., min_length=1, max_length=64)
    expected_revision: int = Field(0, ge=0)

    @model_validator(mode="after")
    def unique_keys(self):
        keys = [row.key for row in self.trainings]
        if len(set(keys)) != len(keys):
            raise ValueError("training keys must be unique")
        return self


class LiteracyAssignmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    person: str = Field(..., pattern=_IDENT)
    roles: list[str] = Field(..., min_length=1, max_length=64)
    expected_revision: int = Field(0, ge=0)


class LiteracyCompletionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    person: str = Field(..., pattern=_IDENT)
    training: str = Field(..., pattern=_IDENT)
    completed_at: float = Field(..., gt=0)
    evidence_ref: str = Field(..., min_length=1, max_length=512)


class IncidentDeclareIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    incident_id: str = Field(..., min_length=1, max_length=64)
    category: str = Field(..., min_length=1, max_length=64)
    widespread: bool = False
    became_aware_at: float = Field(..., gt=0)
    causal_link: str = Field("under_investigation", min_length=1, max_length=64)
    member_state: str = Field(..., min_length=2, max_length=2)
    authority: str = Field(..., min_length=1, max_length=512)


class IncidentSubmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: str = Field(..., pattern=r"^(initial|complete)$")
    submitted_at: float = Field(..., gt=0)
    reference: str = Field(..., min_length=1, max_length=512)
    expected_revision: int = Field(..., ge=1)


class IncidentWithdrawIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rationale: str = Field(..., min_length=1, max_length=2000)
    expected_revision: int = Field(..., ge=1)
