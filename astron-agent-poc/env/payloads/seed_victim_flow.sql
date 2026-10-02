-- astron-agent-poc V3 — victim test flow for the /workflow/v1/resume finding.
--
-- Three-node flow owned by the VICTIM app: start -> question-answer (pauses) -> end.
-- The question-answer node uses needReply=true with direct answers disabled, so the
-- engine raises an INTERRUPT event whose SSE frame discloses the event_id — the
-- observable the PoC's attacker step replays.
--
-- Fill in the placeholders before running:
--   {{VICTIM_APP_ID}}     the victim app's id registered in core-tenant
--   {{QA_MODEL_DOMAIN}}   a model domain available to the deployment (the
--                         question-answer node requires one on some builds)
--   {{FLOW_ID}} / {{GROUP_ID}}  unique ids for your test environment
--
-- The flow must additionally be RELEASED (release_status set to the released value,
-- release_data populated — re-save the flow from the Console designer on your test
-- deployment to produce a valid release_data) and the victim app must be licensed
-- for the flow group the way your deployment binds licenses.
--
-- This SQL seeds a TEST flow with non-sensitive content on a deployment you
-- administer. It contains no real user data.

INSERT INTO workflow.flow
  (id, group_id, name, data, description, version, release_status, app_id, source,
   create_at, tag, update_at)
VALUES
  ({{FLOW_ID}}, {{GROUP_ID}}, 'astron-agent-poc-victim-flow',
   '{"data": {"edges": [{"sourceNodeId": "node-start::6383891d-ce16-4d04-ac82-c9d9287aacc0", "targetNodeId": "question-answer::13c8a5b2-a403-4695-bc09-78be61d39ee7"}, {"sourceNodeId": "question-answer::13c8a5b2-a403-4695-bc09-78be61d39ee7", "targetNodeId": "node-end::42a53121-7120-4eb7-9fb7-08b26aeb04a7"}], "nodes": [{"data": {"inputs": [], "nodeMeta": {"aliasName": "开始", "nodeType": "基础节点"}, "nodeParam": {}, "outputs": [{"id": "ca2aeadf-09c1-43ee-95ed-431d71cabb4e", "name": "AGENT_USER_INPUT", "required": true, "schema": {"description": "用户本轮对话输入内容", "type": "string"}}]}, "id": "node-start::6383891d-ce16-4d04-ac82-c9d9287aacc0"}, {"data": {"inputs": [{"fileType": "", "id": "d20acd99-c6e9-4a69-a1e5-f84aeea87cdf", "name": "input", "schema": {"type": "string", "value": {"content": {"id": "ca2aeadf-09c1-43ee-95ed-431d71cabb4e", "nodeId": "node-start::6383891d-ce16-4d04-ac82-c9d9287aacc0", "name": "AGENT_USER_INPUT"}, "type": "ref"}}}], "nodeMeta": {"aliasName": "问答", "nodeType": "问答节点"}, "nodeParam": {"question": "[astron-agent-poc victim flow] Please confirm to continue. Reply anything to resume.", "answerType": "direct", "timeout": 5, "needReply": true, "directAnswer": {"handleResponse": false, "maxRetryCounts": 1}, "domain": "{{QA_MODEL_DOMAIN}}", "appId": "{{VICTIM_APP_ID}}"}, "outputs": [{"id": "50e04c5d-0228-4120-b635-fe8b94a03ec5", "name": "query", "schema": {"type": "string"}}, {"id": "7a31c063-4b7f-4062-9e47-5030ee953f20", "name": "content", "schema": {"type": "string"}}]}, "id": "question-answer::13c8a5b2-a403-4695-bc09-78be61d39ee7"}, {"data": {"inputs": [{"fileType": "", "id": "bd65ec89-fb71-4bed-93c8-bf5316683a24", "name": "output", "schema": {"type": "string", "value": {"content": {"id": "7a31c063-4b7f-4062-9e47-5030ee953f20", "nodeId": "question-answer::13c8a5b2-a403-4695-bc09-78be61d39ee7", "name": "content"}, "type": "ref"}}}], "nodeMeta": {"aliasName": "结束", "nodeType": "基础节点"}, "nodeParam": {"template": "{{output}}", "streamOutput": true, "templateErrMsg": "", "outputMode": 1}, "outputs": []}, "id": "node-end::42a53121-7120-4eb7-9fb7-08b26aeb04a7"}]}, "description": "astron-agent-poc victim flow", "id": "{{FLOW_ID}}", "name": "astron-agent-poc-victim-flow", "version": "v3.0.0"}}',
   'astron-agent-poc victim flow', 'v1', 0, '{{VICTIM_APP_ID}}', 0, NOW(), 0, NOW());
