"""Provincial privacy law framework mapping for the Canadian Municipal AI Gateway.

Maps Canadian provincial privacy legislation to specific PII categories
detected by the gateway's scrubber. Each framework defines which PII types
are covered, the relevant sections of the law, and the minimum retention
period for audit logs.

Currently implemented:
    - BC FIPPA (complete reference implementation)
    - Alberta FOIPP (placeholder)
    - Ontario MFIPPA (placeholder)
    - Quebec Law 25 (placeholder)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class PiiCoverage:
    """Maps a PII entity type to the section of law that covers it."""
    entity_type: str
    description: str
    legal_section: str
    legal_text: str


@dataclass
class ProvincialFramework:
    """A provincial privacy framework and its requirements."""
    province_code: str
    framework_name: str
    full_title: str
    summary: str
    audit_retention_days: int
    pii_coverage: list[PiiCoverage] = field(default_factory=list)
    key_requirements: list[str] = field(default_factory=list)
    status: str = "complete"


# ── BC FIPPA (Freedom of Information and Protection of Privacy Act) ──────────

BC_FIPPA = ProvincialFramework(
    province_code="BC",
    framework_name="FIPPA",
    full_title="Freedom of Information and Protection of Privacy Act, RSBC 1996, c. 165",
    summary=(
        "BC FIPPA governs how public bodies collect, use, disclose, and protect "
        "personal information. It requires that personal information be stored and "
        "accessed only in Canada unless specific exceptions apply. Public bodies must "
        "protect personal information with reasonable security arrangements."
    ),
    audit_retention_days=365,
    pii_coverage=[
        PiiCoverage(
            entity_type="PERSON",
            description="Names of individuals",
            legal_section="s. 22(1)",
            legal_text="Personal information is protected from disclosure if it would be an unreasonable invasion of a third party's personal privacy.",
        ),
        PiiCoverage(
            entity_type="CA_SIN",
            description="Social Insurance Numbers",
            legal_section="s. 22(3)(b)",
            legal_text="An identifying number assigned to the individual by a public body. SINs are presumed to be an unreasonable invasion of privacy if disclosed.",
        ),
        PiiCoverage(
            entity_type="CA_BC_PHN",
            description="BC Personal Health Numbers",
            legal_section="s. 22(3)(b)",
            legal_text="An identifying number assigned to the individual. Health numbers are covered as personal identifiers under FIPPA and additionally protected under the E-Health Act.",
        ),
        PiiCoverage(
            entity_type="EMAIL_ADDRESS",
            description="Email addresses",
            legal_section="s. 22(1)",
            legal_text="Contact information that could identify an individual. Protected from disclosure if it would unreasonably invade privacy.",
        ),
        PiiCoverage(
            entity_type="CA_PHONE_NUMBER",
            description="Phone numbers",
            legal_section="s. 22(1)",
            legal_text="Contact information that could identify an individual. Protected under the general personal privacy provisions.",
        ),
        PiiCoverage(
            entity_type="CA_POSTAL_CODE",
            description="Canadian postal codes",
            legal_section="s. 22(1)",
            legal_text="Address information that can be used to identify an individual's residence. When combined with other information, postal codes can identify individuals.",
        ),
        PiiCoverage(
            entity_type="CA_ADDRESS",
            description="Street addresses",
            legal_section="s. 22(3)(d)",
            legal_text="The individual's home address or telephone number. Home address is explicitly listed as information where disclosure is presumed to be an unreasonable invasion of privacy.",
        ),
        PiiCoverage(
            entity_type="LOCATION",
            description="Location references detected by NLP",
            legal_section="s. 22(1)",
            legal_text="Location information that could identify an individual when combined with other personal information in the same request.",
        ),
        PiiCoverage(
            entity_type="CA_PID",
            description="BC Parcel Identifiers",
            legal_section="s. 22(1)",
            legal_text="Property identifiers that can be cross-referenced with land title records to identify property owners. Considered personal information in context.",
        ),
        PiiCoverage(
            entity_type="CA_FOLIO",
            description="Municipal assessment folio numbers",
            legal_section="s. 22(1)",
            legal_text="Municipal property assessment identifiers that link to owner information in assessment rolls.",
        ),
        PiiCoverage(
            entity_type="CA_CASE_NUMBER",
            description="Municipal application case numbers",
            legal_section="s. 22(1)",
            legal_text="Case numbers for bylaw applications, permits, and variances that can be linked to applicant personal information.",
        ),
    ],
    key_requirements=[
        "s. 30: Protect personal information with reasonable security arrangements against unauthorized access, collection, use, disclosure, or disposal.",
        "s. 30.1: Store personal information only in Canada and ensure access only from within Canada, unless authorized by regulation.",
        "s. 31: Retain personal information for at least one year after it is used to make a decision directly affecting the individual.",
        "s. 26: Collect personal information only if it relates directly to and is necessary for an operating program or activity of the public body.",
        "s. 32: Use personal information only for the purpose for which it was collected, or for a consistent purpose.",
        "s. 33: Disclose personal information only as authorized under FIPPA.",
    ],
    status="complete",
)

# ── Alberta FOIPP (Freedom of Information and Protection of Privacy Act) ──────

AB_FOIPP = ProvincialFramework(
    province_code="AB",
    framework_name="FOIPP",
    full_title="Freedom of Information and Protection of Privacy Act, RSA 2000, c. F-25",
    summary=(
        "Alberta FOIPP governs the collection, use, and disclosure of personal "
        "information by public bodies in Alberta. It requires reasonable security "
        "measures and limits collection to information directly related to operating "
        "programs."
    ),
    audit_retention_days=365,
    pii_coverage=[
        PiiCoverage(
            entity_type="PERSON",
            description="Names of individuals",
            legal_section="s. 1(n)",
            legal_text="Personal information includes the name of an individual where it appears with other personal information or where its disclosure would reveal other personal information.",
        ),
        PiiCoverage(
            entity_type="CA_SIN",
            description="Social Insurance Numbers",
            legal_section="s. 1(n)(viii)",
            legal_text="An identifying number or symbol assigned to the individual.",
        ),
        PiiCoverage(
            entity_type="CA_AB_PHN",
            description="Alberta Personal Health Numbers (ULI)",
            legal_section="s. 1(n)(viii)",
            legal_text="An identifying number assigned to the individual by the Alberta Health Care Insurance Plan. Additionally protected under Alberta's Health Information Act.",
        ),
        # Additional entity types (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, etc.)
        # are covered by FOIPP s. 1(n) broadly. Specific section mappings for
        # these general types are not included because FOIPP defines personal
        # information as a category rather than enumerating each data element.
    ],
    key_requirements=[
        "s. 38: Protect personal information with reasonable security arrangements.",
        "s. 35: Retain personal information for a reasonable period so individuals can exercise their right of access.",
        "s. 33: Collect personal information only if it relates directly to and is necessary for an operating program or activity.",
        "s. 39: Use personal information only for the purpose for which it was collected, or for a consistent purpose.",
        "s. 40: Disclose personal information only as authorized under FOIPP.",
    ],
    status="placeholder",
)

# ── Ontario MFIPPA (Municipal Freedom of Information and Protection of Privacy Act)

ON_MFIPPA = ProvincialFramework(
    province_code="ON",
    framework_name="MFIPPA",
    full_title="Municipal Freedom of Information and Protection of Privacy Act, RSO 1990, c. M.56",
    summary=(
        "Ontario MFIPPA governs how municipalities and local boards collect, use, "
        "and disclose personal information. It applies specifically to municipal "
        "institutions rather than provincial government bodies."
    ),
    audit_retention_days=365,
    pii_coverage=[
        PiiCoverage(
            entity_type="PERSON",
            description="Names of individuals",
            legal_section="s. 2(1)",
            legal_text="Personal information means recorded information about an identifiable individual, including the name where it appears with other personal information.",
        ),
        PiiCoverage(
            entity_type="CA_SIN",
            description="Social Insurance Numbers",
            legal_section="s. 2(1)",
            legal_text="An identifying number assigned to the individual.",
        ),
        PiiCoverage(
            entity_type="CA_ON_OHIP",
            description="Ontario Health Insurance Plan numbers",
            legal_section="s. 2(1)",
            legal_text="An identifying number assigned to the individual. Additionally protected under Ontario's Personal Health Information Protection Act (PHIPA).",
        ),
        # Additional entity types are covered by MFIPPA s. 2(1) broadly.
        # Ontario's definition of personal information is inclusive rather
        # than enumerative, so specific section mappings per entity type
        # are not required.
    ],
    key_requirements=[
        "s. 28(2): Take reasonable steps to ensure personal information is accurate and up to date.",
        "s. 28(1): Retain personal information for the minimum period required to allow individuals access rights.",
        "s. 28(2): Protect personal information with reasonable security measures.",
        "s. 28-29: Collect personal information only if authorized by statute or necessary for the proper administration of a lawfully authorized activity.",
        "s. 31: Use personal information only for the purpose for which it was collected, or for a consistent purpose.",
        "s. 32: Disclose personal information only as authorized under MFIPPA.",
    ],
    status="placeholder",
)

# ── Quebec Law 25 (Act to modernize legislative provisions as regards the
#    protection of personal information) ──────────────────────────────────────

QC_LAW25 = ProvincialFramework(
    province_code="QC",
    framework_name="Law 25",
    full_title="Act to modernize legislative provisions as regards the protection of personal information (Bill 64 / Law 25)",
    summary=(
        "Quebec Law 25 modernized Quebec's privacy framework with stricter "
        "requirements for consent, data minimization, privacy impact assessments, "
        "and breach notification. It is the strictest provincial privacy framework "
        "in Canada and applies to both public and private sector organizations."
    ),
    audit_retention_days=730,
    pii_coverage=[
        PiiCoverage(
            entity_type="PERSON",
            description="Names of individuals",
            legal_section="s. 54",
            legal_text="Personal information means any information which relates to a natural person and allows that person to be identified.",
        ),
        PiiCoverage(
            entity_type="CA_SIN",
            description="Social Insurance Numbers",
            legal_section="s. 54",
            legal_text="An identifying number assigned to the individual. SINs receive heightened protection as sensitive personal information.",
        ),
        PiiCoverage(
            entity_type="CA_QC_RAMQ",
            description="Quebec Health Insurance (RAMQ) numbers",
            legal_section="s. 54",
            legal_text="An identifying number assigned by the Regie de l'assurance maladie du Quebec. Considered sensitive personal information under Law 25.",
        ),
        # Additional entity types are covered by Law 25 s. 2 and s. 12 broadly.
        # Law 25 classifies certain categories (biometrics, health, financial)
        # as sensitive personal information with heightened protections under
        # s. 12. General entity types like names and emails fall under the
        # standard personal information definition.
    ],
    key_requirements=[
        "Privacy impact assessments are mandatory before collecting personal information for any new project or system.",
        "Consent must be clear, free, and informed. Implied consent is not sufficient for sensitive personal information.",
        "Data minimization: collect only the personal information necessary for the stated purpose.",
        "Breach notification to the Commission d'acces within 72 hours of becoming aware of a confidentiality incident.",
        "Designate a person responsible for the protection of personal information and publish their title and contact information.",
        "Anonymization or destruction of personal information once the purpose of collection has been achieved.",
    ],
    status="placeholder",
)

# ── Framework registry ────────────────────────────────────────────────────────

FRAMEWORKS = {
    "BC": BC_FIPPA,
    "AB": AB_FOIPP,
    "ON": ON_MFIPPA,
    "QC": QC_LAW25,
}


def get_active_framework() -> ProvincialFramework | None:
    """Return the framework for the province set in the PROVINCE env var.

    Returns None if PROVINCE is not set or not recognized.
    """
    province = os.getenv("PROVINCE", "").strip().upper()
    return FRAMEWORKS.get(province)


def get_framework(province_code: str) -> ProvincialFramework | None:
    """Return the framework for a specific province code."""
    return FRAMEWORKS.get(province_code.upper())


def list_frameworks() -> list[dict]:
    """Return a summary of all available frameworks."""
    return [
        {
            "province_code": fw.province_code,
            "framework_name": fw.framework_name,
            "full_title": fw.full_title,
            "status": fw.status,
        }
        for fw in FRAMEWORKS.values()
    ]


def framework_to_dict(fw: ProvincialFramework) -> dict:
    """Serialize a framework to a JSON-friendly dict."""
    return {
        "province_code": fw.province_code,
        "framework_name": fw.framework_name,
        "full_title": fw.full_title,
        "summary": fw.summary,
        "audit_retention_days": fw.audit_retention_days,
        "status": fw.status,
        "pii_coverage": [
            {
                "entity_type": p.entity_type,
                "description": p.description,
                "legal_section": p.legal_section,
                "legal_text": p.legal_text,
            }
            for p in fw.pii_coverage
        ],
        "key_requirements": fw.key_requirements,
    }
