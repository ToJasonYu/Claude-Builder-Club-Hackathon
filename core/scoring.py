from core.models import (
    EaseOfRemediation,
    DataSensitivity,
    FindingFile,
    NGOProfile,
    PopulationServed,
    SISBreakdown,
    SISResult,
    VulnerabilityFinding,
)

POPULATION_SCORES: dict[PopulationServed, int] = {
    "refugees": 40,
    "domestic_violence_survivors": 40,
    "children": 35,
    "elderly": 30,
    "general_public": 10,
}

DATA_SENSITIVITY_SCORES: dict[DataSensitivity, int] = {
    "medical": 40,
    "location": 40,
    "financial": 35,
    "general_pii": 25,
    "non_personal": 10,
}

EASE_OF_REMEDIATION_SCORES: dict[EaseOfRemediation, int] = {
    "high": 20,
    "medium": 12,
    "complex": 5,
}

POPULATION_LABELS: dict[PopulationServed, str] = {
    "refugees": "Refugees",
    "domestic_violence_survivors": "Domestic Violence Survivors",
    "children": "Children",
    "elderly": "Elderly Individuals",
    "general_public": "General Public",
}

DATA_SENSITIVITY_LABELS: dict[DataSensitivity, str] = {
    "medical": "Medical / Health Records",
    "location": "Location / Physical Safety Data",
    "financial": "Financial Information",
    "general_pii": "General Personal Information",
    "non_personal": "Non-Personal Data",
}

EASE_LABELS: dict[EaseOfRemediation, str] = {
    "high": "Easy (configuration change)",
    "medium": "Moderate (code fix required)",
    "complex": "Complex (architectural change needed)",
}


def calculate_sis(finding: VulnerabilityFinding, ngo: NGOProfile) -> SISResult:
    pop_score = POPULATION_SCORES[ngo.population_served]
    data_score = DATA_SENSITIVITY_SCORES[finding.data_sensitivity]
    ease_score = EASE_OF_REMEDIATION_SCORES[finding.ease_of_remediation]
    total = pop_score + data_score + ease_score
    return SISResult(
        finding_id=finding.id,
        population_score=pop_score,
        data_sensitivity_score=data_score,
        ease_of_remediation_score=ease_score,
        total_sis=total,
        breakdown=SISBreakdown(
            population_served=ngo.population_served,
            data_sensitivity=finding.data_sensitivity,
            ease_of_remediation=finding.ease_of_remediation,
        ),
    )


def calculate_all_sis(finding_file: FindingFile) -> list[SISResult]:
    return [
        calculate_sis(finding, finding_file.ngo)
        for finding in finding_file.findings
    ]
