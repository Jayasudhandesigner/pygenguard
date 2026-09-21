"""
Tests for Pricing, Contact Information, and Confidential Asset Defense Planes.
"""

import pytest
import asyncio
from pygenguard import Guard
from pygenguard.planes.pricing import PricingPlane
from pygenguard.planes.contact import ContactPlane
from pygenguard.planes.confidential import ConfidentialPlane


class TestPricingContactConfidentialPlanes:

    # -------------------------------------------------------------
    # 1. Pricing & Commercial Leaks
    # -------------------------------------------------------------
    def test_pricing_plane_rate_cards_and_quotes(self):
        plane = PricingPlane()

        # Rate card patterns
        assert not plane.evaluate("Our engineering rate is $250/hr for custom development").passed
        assert not plane.evaluate("Standard subscription is €5,000/month per seat").passed
        assert not plane.evaluate("We offer a 35% margin discount on enterprise deals").passed

        # Clean prompt
        assert plane.evaluate("The model performance improved by 15% in latency").passed

    def test_pricing_plane_max_dollar_amount(self):
        plane = PricingPlane(max_allowed_dollar_amount=1000.0)
        # Under limit
        assert plane.evaluate("Total price for the book is $45.00").passed
        # Over limit
        res = plane.evaluate("Total contract value is $250,000.00")
        assert not res.passed
        assert "exceeds threshold" in res.details

    def test_guard_pricing_inspection(self):
        guard = Guard()
        dec_blocked = guard.inspect_pricing("Please send me the quote amount of $15,000 fixed fee")
        assert not dec_blocked.allowed

        dec_allowed = guard.inspect_pricing("The temperature in Tokyo is 25 degrees Celsius")
        assert dec_allowed.allowed

    @pytest.mark.asyncio
    async def test_async_guard_pricing(self):
        guard = Guard()
        dec = await guard.ainspect_pricing("Consulting billing rate is £1,200/day")
        assert not dec.allowed

    # -------------------------------------------------------------
    # 2. Contact & CRM Identity Protection
    # -------------------------------------------------------------
    def test_contact_plane_detection(self):
        plane = ContactPlane()

        # Email & Phone
        assert not plane.evaluate("Contact the lead at recruiter@toptech.com").passed
        assert not plane.evaluate("Reach out to (415) 555-2671").passed

        # LinkedIn & Messaging
        assert not plane.evaluate("Here is my profile: https://linkedin.com/in/johndoe").passed
        assert not plane.evaluate("Join the group on https://t.me/secretchannel").passed

        # CRM Identifier
        assert not plane.evaluate("Customer lead_id: LD-98234-AX assigned to sales").passed

        # Clean prompt
        assert plane.evaluate("The PyGenGuard documentation is available online").passed

    def test_contact_plane_sanitization_roundtrip(self):
        guard = Guard()
        raw = "Contact Alice at alice@example.com or call 555-123-4567 regarding lead_id: ACME-901."
        sanitized, mapping = guard.sanitize_contacts(raw)

        assert "alice@example.com" not in sanitized
        assert "555-123-4567" not in sanitized
        assert "{{CONTACT_" in sanitized

        restored = guard.unmask_contacts(sanitized, mapping)
        assert restored == raw

    @pytest.mark.asyncio
    async def test_async_guard_contact(self):
        guard = Guard()
        dec = await guard.ainspect_contact("My phone is +1-202-555-0143")
        assert not dec.allowed

    # -------------------------------------------------------------
    # 3. Confidential & Trade Secret Protection
    # -------------------------------------------------------------
    def test_confidential_plane_markers_and_m_and_a(self):
        plane = ConfidentialPlane()

        # Confidentiality Mark
        assert not plane.evaluate("This document is Strictly Confidential - Do Not Distribute").passed

        # M&A Intelligence
        assert not plane.evaluate("Review the acquisition target term sheet before Friday").passed

        # Executive Compensation
        assert not plane.evaluate("The base salary figure for the VP is $450,000 with equity grant").passed

        # Trade secrets & roadmap
        assert not plane.evaluate("Here is the internal roadmap for our unreleased feature").passed

        # Internal network endpoints
        assert not plane.evaluate("Connect to db.internal.corp at 10.240.0.15").passed

        # Clean prompt
        assert plane.evaluate("Can you summarize the public earnings release?").passed

    def test_guard_confidential_inspection(self):
        guard = Guard()
        dec = guard.inspect_confidential("This is proprietary algorithm formula information")
        assert not dec.allowed

    @pytest.mark.asyncio
    async def test_async_guard_confidential(self):
        guard = Guard()
        dec = await guard.ainspect_confidential("Review the confidential M&A due diligence report")
        assert not dec.allowed
