# From Detection to Governance

The Canadian Municipal AI Gateway shows you what's happening. It doesn't tell you what to do about it.

---

## What the gateway tells you

After 30 days of running the gateway, you'll know:

- **How many AI requests** your staff are making, by department and provider
- **What PII was detected and scrubbed** -- SINs, health numbers, addresses, names, phone numbers
- **Your PII detection rate** -- the percentage of requests that contained personal information before scrubbing
- **Which models and providers** each department is using
- **How much it costs** -- token usage and estimated spend per department
- **Whether your audit chain is intact** -- tamper-evident proof that logs haven't been altered

This is the technical layer. It's necessary. It's not sufficient.

---

## What the gateway can't tell you

The gateway has no opinion on any of the following:

- **Was this use approved?** A planning analyst using GPT-4 to draft a report -- is that within policy? Who approved it? When?
- **Which privacy frameworks apply?** BC FIPPA, Alberta FOIPP, Ontario MFIPPA, Quebec Law 25 -- each has different requirements for AI use involving personal information. The gateway doesn't map your usage to your obligations.
- **How do you defend this to council?** When a councillor asks "what are we doing about AI risk?" -- your PII detection chart is a start, but it's not a governance answer.
- **What's your acceptable use policy?** The gateway enforces rate limits and model restrictions. It doesn't define what "acceptable use" means for your organization.
- **Are you ready for a privacy commissioner inquiry?** If OIPC BC or the Ontario IPC asks how your municipality governs AI use, the gateway logs are evidence -- but they're not a compliance program.

---

## The governance gap

After the gateway is running, most municipalities find themselves in this position:

> "We can see the problem now. 12% of our AI requests contained PII before scrubbing. We have audit logs. We have rate limits. But we don't have a documented AI governance program, we don't have council approval, and we don't have a defensible answer for a privacy commissioner."

The gateway closes the **technical gap**. The **governance gap** remains:

- No documented decision-making framework for AI use
- No regulatory mapping to provincial privacy legislation
- No board-ready compliance reports
- No Privacy Impact Assessment on file
- No acceptable use policy approved by council
- No defensible audit trail that connects technical controls to governance decisions

---

## How LUMINARYX fills that gap

[LUMINARYX](https://luminaryx.ca) is the governance layer that sits on top of the gateway.

**Decision approvals** -- Documented, time-stamped records of who approved what AI use, under what conditions, with what safeguards.

**Regulatory framework mapping** -- Your AI usage mapped to your specific provincial privacy obligations. BC FIPPA section references, not generic "privacy best practices."

**Board-ready compliance reports** -- Reports your CAO can put in front of council that show governance in action, not just technical controls.

**Privacy Impact Assessments** -- Structured PIAs that satisfy commissioner expectations, built from your actual gateway data.

**Defensible audit trail** -- The gateway proves what happened technically. LUMINARYX proves it was governed.

Together, the gateway and LUMINARYX answer every question a privacy commissioner will ask:

1. What AI tools are your staff using? *(Gateway: usage logs)*
2. What personal information is involved? *(Gateway: PII detection)*
3. What controls are in place? *(Gateway: scrubbing, rate limits, model restrictions)*
4. Who approved this use? *(LUMINARYX: decision records)*
5. What privacy framework governs it? *(LUMINARYX: regulatory mapping)*
6. How do you monitor compliance? *(Both: gateway data + LUMINARYX reports)*

---

**The gateway is free, open-source, and yours to run forever.**

**When you're ready to close the governance gap: [luminaryx.ca](https://luminaryx.ca)**
