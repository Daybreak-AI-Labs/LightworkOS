"""Synthetic local chat lifecycle data; no inference or customer work."""
from maverick.paths import tenant_scope


def install(app, world, tenant, principal):
    @app.post("/__browser_fixture/print", include_in_schema=False)
    async def fixture_print():
        cells = ["LongUnbrokenCell" * 12] * 8
        result = "\n".join((
            "| " + " | ".join(f"Column {index}" for index in range(8)) + " |",
            "| " + " | ".join(["---"] * 8) + " |",
            "| " + " | ".join(cells) + " |",
            "",
            "```text",
            "LongUnbrokenCode" * 120,
            "```",
            "",
            *(f"Printed paragraph {index}: all content must remain available across pages.\n"
              for index in range(1, 81)),
        ))
        with tenant_scope(tenant=tenant):
            print_goal = world.create_goal("Wide print result", "Synthetic print review", owner=principal)
            world.set_goal_status(print_goal, "done", result=result)
        return {"synthetic": True, "goal_id": print_goal}

    @app.post("/__browser_fixture/chat", include_in_schema=False)
    async def fixture_chat():
        # Dedicated records per journey. The stored transcript deliberately
        # differs from the edited result so older actions must retain its bytes.
        with tenant_scope(tenant=tenant):
            root_id = world.create_goal("Earlier request", "", owner=principal)
            world.set_goal_status(root_id, "done", result="Earlier answer after an edit.")
            conversation = world.get_or_create_conversation("web", f"{principal}/{root_id}")
            world.append_turn(conversation.id, "user", "Earlier request", goal_id=root_id)
            world.append_turn(conversation.id, "assistant", "Earlier answer as originally delivered.", goal_id=root_id)
            current_id = world.create_goal("Continue the conversation", "", owner=principal, parent_id=root_id)
            world.append_turn(conversation.id, "user", "Continue the conversation", goal_id=current_id)
            world.set_goal_status(current_id, "running")
            question_id = world.ask("Which delivery date should I use?", goal_id=current_id)
            world.answer(question_id, "Use Friday.")
        return {"synthetic": True, "root_id": root_id, "goal_id": current_id}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/finish", include_in_schema=False)
    async def fixture_chat_finish(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_status(chat_goal_id, "done", result="## Finished answer\n\nDelivery is planned for Friday.")
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/restart", include_in_schema=False)
    async def fixture_chat_restart(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_status(chat_goal_id, "running", result="")
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/provider-fail", include_in_schema=False)
    async def fixture_chat_provider_fail(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_status(chat_goal_id, "blocked", result="provider connection refused")
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/activity", include_in_schema=False)
    async def fixture_chat_activity(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.append_event(chat_goal_id, "orchestrator", "plan",
                               "role=orchestrator depth=0 brief=INTERNAL PROMPT ## Prior failures")
            world.append_event(chat_goal_id, "orchestrator", "observation", "private model scratch text")
            world.append_event(chat_goal_id, "orchestrator", "observation",
                               "tool=ask_user -> <tool_output tool='ask_user'>QUEUED question #2</tool_output>")
            world.append_event(chat_goal_id, "reviewer", "finding", "The invoice matches the purchase order.")
            world.set_goal_status(chat_goal_id, "done", result="The invoice matches the purchase order.")
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/pilot-prepared", include_in_schema=False)
    async def fixture_chat_pilot_prepared(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_status(chat_goal_id, "blocked", result=(
                "Prepared for a workflow pilot. Start this task after the pilot plan is frozen."))
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/chat/{chat_goal_id}/specialist-setup-fail", include_in_schema=False)
    async def fixture_chat_specialist_setup_fail(chat_goal_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_domain(chat_goal_id, "legal_research")
            world.set_goal_status(chat_goal_id, "blocked", result=(
                "domain 'legal_research' agent build failed: Domain 'legal_research' "
                "cannot deploy: required workflow tools unavailable: web_search. "
                "No model work has started."))
        return {"synthetic": True, "provider_calls": 0}

    @app.post("/__browser_fixture/long-chat", include_in_schema=False)
    async def fixture_long_chat():
        with tenant_scope(tenant=tenant):
            root_id = world.create_goal("Long local conversation", owner=principal)
            conversation = world.get_or_create_conversation("web", f"{principal}/{root_id}")
            for index in range(26):
                world.append_turn(conversation.id, "user", f"Earlier request {index + 1}", goal_id=root_id)
                world.append_turn(conversation.id, "assistant", f"Earlier answer {index + 1}", goal_id=root_id)
            world.set_goal_status(root_id, "done", result="Earlier answer 26")
            current_id = world.create_goal("Current request", owner=principal, parent_id=root_id)
            world.append_turn(conversation.id, "user", "Current request", goal_id=current_id)
            world.set_goal_status(current_id, "done", result="Current answer")
            world.append_turn(conversation.id, "assistant", "Current answer", goal_id=current_id)
        return {"synthetic": True, "goal_id": current_id, "provider_calls": 0}

    @app.post("/__browser_fixture/conversation-share", include_in_schema=False)
    async def fixture_conversation_share():
        with tenant_scope(tenant=tenant):
            root_id = world.create_goal("Prior launch request", "INTERNAL ROOT NOTES", owner=principal,
                                        domain="finance_cash13w")
            world.set_goal_status(root_id, "done", result="Approved initial answer.")
            world.record_signoff(root_id, "approved", decided_by=principal)
            conversation = world.get_or_create_conversation("web", f"{principal}/{root_id}")
            world.append_turn(conversation.id, "user", "What can we automate first?", goal_id=root_id)
            world.append_turn(conversation.id, "assistant", "Approved initial answer.", goal_id=root_id)
            question_id = world.ask("Which location matters?", goal_id=root_id)
            world.answer(question_id, "Chattanooga")
            current_id = world.create_goal("Build the next step", owner=principal, parent_id=root_id)
            world.set_goal_status(current_id, "done", result="## Current answer\n\nStart with the next step.")
            world.append_turn(conversation.id, "user", "Build the next step", goal_id=current_id)
            world.append_turn(conversation.id, "assistant", "## Current answer\n\nStart with the next step.", goal_id=current_id)
            world.add_artifact(current_id, "text", "Private attachment", "PRIVATE ATTACHMENT BODY")
        return {"synthetic": True, "root_id": root_id, "goal_id": current_id}

    @app.post("/__browser_fixture/conversation-share/{root_id}/change-source", include_in_schema=False)
    async def fixture_share_change_source(root_id: int):
        with tenant_scope(tenant=tenant):
            world.set_goal_status(root_id, "done", result="Approved initial answer was amended.")
            world.record_signoff(root_id, "approved", decided_by=principal)
        return {"synthetic": True}

    @app.post("/__browser_fixture/conversation-share/{root_id}/reject", include_in_schema=False)
    async def fixture_share_reject(root_id: int):
        with tenant_scope(tenant=tenant):
            world.record_signoff(root_id, "rejected", decided_by=principal)
        return {"synthetic": True}
