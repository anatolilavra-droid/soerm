-- SOERM M13 workspace database, as a plain SQL dump.
--
-- Schema version: 2 (the schema released with M13)
--   1 initial_schema  d7c8ce7fa4af8f2b27925f95c0f10e5f87b6257d59c063096d48ec67346bea61
--   2 playbook_runs   76b5ee60b77c7dee73bc4105eb3f0a15917fce46510eebe1752d73860878ce62
--
-- Produced by the released M13 code (commit edfbb03) running the end-to-end scenario of
-- README.md (section M11) on a copy of examples/sample_workspace: one asset; SARIF, JSON and
-- CSV imports; risk recalculation; a task; an incident with the phishing playbook attached,
-- two steps done, one of them through an approved change (CHG-000001, actor bob).
-- Then dumped with sqlite3's iterdump() from a read-only connection.
--
-- Audit chain at dump time: 26 entries, head
-- 6107ca21836a715eafc51dfc6c231912d49cafac1d60f060f0c99c6eb12eb169
--
-- A text dump instead of a .db file: databases are never committed (.gitignore,
-- tests/unit/test_repo_hygiene.py, CI). Do not edit by hand; its SHA-256 is pinned in
-- tests/unit/storage/test_m13_fixture.py.
BEGIN TRANSACTION;
CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY CHECK ((asset_id GLOB 'AST-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(asset_id) BETWEEN 10 AND 16 AND substr(asset_id, 5) NOT GLOB '*[^0-9]*')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    environment TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'test')),
    business_criticality TEXT NOT NULL CHECK (business_criticality IN ('low', 'medium', 'high', 'critical')),
    data_classification TEXT NOT NULL CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted')),
    exposure TEXT NOT NULL CHECK (exposure IN ('internet', 'partner', 'internal', 'isolated')),
    tags TEXT NOT NULL CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (updated_at >= created_at)
) STRICT;
INSERT INTO "assets" VALUES('AST-000001','Billing API','platform','production','high','confidential','internet','[]','2026-10-28T20:07:56.782189Z','2026-10-28T20:07:56.782189Z');
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    ts TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    actor TEXT NOT NULL CHECK ((actor GLOB '[a-z0-9]*' AND length(actor) BETWEEN 1 AND 128 AND actor NOT GLOB '*[^a-z0-9._@+-]*')),
    action TEXT NOT NULL CHECK ((action GLOB '[a-z]*' AND length(action) BETWEEN 2 AND 64 AND action NOT GLOB '*[^a-z0-9_.]*')),
    object_type TEXT NOT NULL CHECK ((object_type GLOB '[a-z]*' AND length(object_type) BETWEEN 2 AND 64 AND object_type NOT GLOB '*[^a-z0-9_-]*')),
    object_id TEXT NOT NULL CHECK ((length(object_id) BETWEEN 1 AND 64 AND object_id NOT GLOB '*[^A-Za-z0-9._:-]*')),
    before_hash TEXT CHECK ((before_hash IS NULL OR (length(before_hash) = 64 AND before_hash NOT GLOB '*[^0-9a-f]*'))),
    after_hash TEXT CHECK ((after_hash IS NULL OR (length(after_hash) = 64 AND after_hash NOT GLOB '*[^0-9a-f]*'))),
    prev_hash TEXT NOT NULL CHECK ((length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*')),
    entry_hash TEXT NOT NULL UNIQUE CHECK ((length(entry_hash) = 64 AND entry_hash NOT GLOB '*[^0-9a-f]*'))
) STRICT;
INSERT INTO "audit_log" VALUES(1,'2026-10-28T20:07:56.782189Z','alice','asset.create','asset','AST-000001',NULL,'297646d3a17479e6626a29f5c78a06a1c2ed292ceb8facd2a7d3ecbc132a2086','0000000000000000000000000000000000000000000000000000000000000000','7102efe496479b170788648d9db4bc2283237e5f58f6cd2440929844f51ec208');
INSERT INTO "audit_log" VALUES(2,'2026-10-28T20:07:57.233423Z','alice','import.run','import_run','RUN-000001',NULL,'aca5125f05875745be9574ee2ec20d5165e8e65da68ecbdd63e06daa9a65d91d','7102efe496479b170788648d9db4bc2283237e5f58f6cd2440929844f51ec208','7facf2d322cf9aac56ec401bcadaba6a82aeb232979fa5b27d0b469030098be6');
INSERT INTO "audit_log" VALUES(3,'2026-10-28T20:07:57.233423Z','alice','finding.create','finding','FND-000001',NULL,'8416820f0d2d91b4c17394ab166467382916c957615998df9544529fed3cbace','7facf2d322cf9aac56ec401bcadaba6a82aeb232979fa5b27d0b469030098be6','ff9a166751aeca90c52cac24d2d872aa67a109394f6b9f0f808755aabdca37e3');
INSERT INTO "audit_log" VALUES(4,'2026-10-28T20:07:57.233423Z','alice','finding.create','finding','FND-000002',NULL,'21c50e0c8f4f57b1317178693daad3e1e7e47eb5e31950257807a065fefe437e','ff9a166751aeca90c52cac24d2d872aa67a109394f6b9f0f808755aabdca37e3','3b155ba5b997078d346f9d9c0f8464c20d7a79d6de12b2a09809ff1a4d5f534c');
INSERT INTO "audit_log" VALUES(5,'2026-10-28T20:07:57.693817Z','alice','import.run','import_run','RUN-000002',NULL,'03955ac8c35c889449467cf6f54429466a75341368cffd8772fce0fad6b652d5','3b155ba5b997078d346f9d9c0f8464c20d7a79d6de12b2a09809ff1a4d5f534c','c1735910ec6f668d06c6d9115777715ffaefa4dedbced072d1a5126d0a1f535d');
INSERT INTO "audit_log" VALUES(6,'2026-10-28T20:07:57.693817Z','alice','finding.create','finding','FND-000003',NULL,'e6ef7240a067be4530c65a09fd3ca06481eb2ea136bdbe5721f1fb3997028c99','c1735910ec6f668d06c6d9115777715ffaefa4dedbced072d1a5126d0a1f535d','f1536c4fc0ae207ddf8fd27a0fb7b9d8f8ab975ba5a493a211da15f011425c56');
INSERT INTO "audit_log" VALUES(7,'2026-10-28T20:07:57.693817Z','alice','finding.create','finding','FND-000004',NULL,'701ecf5f3a454ad4896d3cbfb7bf2a3bd571fa762be714cb685e7ecec6a1a40c','f1536c4fc0ae207ddf8fd27a0fb7b9d8f8ab975ba5a493a211da15f011425c56','5d77f2ba87e7cc719a498ed1b0293e36994626d16c3f8bb0f2aa53097234e4c2');
INSERT INTO "audit_log" VALUES(8,'2026-10-28T20:07:58.108479Z','alice','import.run','import_run','RUN-000003',NULL,'5fac321d42bab0b3fecf04e216936c6666e98b0a3a35cc2953111f6c5979fdce','5d77f2ba87e7cc719a498ed1b0293e36994626d16c3f8bb0f2aa53097234e4c2','75747e45a04036c338bb0157941ec79030c2f3e3c68a44d11d9e83e4818527ff');
INSERT INTO "audit_log" VALUES(9,'2026-10-28T20:07:58.108479Z','alice','finding.create','finding','FND-000005',NULL,'5ae24c9903ed16309283db32fb4416a5ee570a23be63aafdd76fdb6a8c7525db','75747e45a04036c338bb0157941ec79030c2f3e3c68a44d11d9e83e4818527ff','e433a60c246d7d48cfa0439faa9b01b80679c2969dc6ff7103adce72f48e7166');
INSERT INTO "audit_log" VALUES(10,'2026-10-28T20:07:58.108479Z','alice','finding.create','finding','FND-000006',NULL,'79af92ec3347a8638926cd3f7c0ab03882af4721913335ca15bfe528879133fa','e433a60c246d7d48cfa0439faa9b01b80679c2969dc6ff7103adce72f48e7166','184e0fd2d295228e1239912a72c4f45e2bd02570990a324f7aafcd31ff901a0a');
INSERT INTO "audit_log" VALUES(11,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000001','8416820f0d2d91b4c17394ab166467382916c957615998df9544529fed3cbace','6e721feb23ee377b431bb7f43100dd2c825659b3c33d0671436b95ec779e3e6a','184e0fd2d295228e1239912a72c4f45e2bd02570990a324f7aafcd31ff901a0a','60485def607385be4518900638a59a2fe329806b65220cffb318abdd28a5d685');
INSERT INTO "audit_log" VALUES(12,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000002','21c50e0c8f4f57b1317178693daad3e1e7e47eb5e31950257807a065fefe437e','818c352e37abbfa2a3a91837d3169ba8abe81aec45da1f23378064debc6c71e8','60485def607385be4518900638a59a2fe329806b65220cffb318abdd28a5d685','5452fba2b23847858f0317f35ea755969fb718f62867d94695e1b5c6075ef0db');
INSERT INTO "audit_log" VALUES(13,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000003','e6ef7240a067be4530c65a09fd3ca06481eb2ea136bdbe5721f1fb3997028c99','a3c6d4b85e48c613f161c996412be1a9ff95c9f789d53b09ac7149bc35521058','5452fba2b23847858f0317f35ea755969fb718f62867d94695e1b5c6075ef0db','9d5c5a8aea9f660eebf054312e21fce16038b6c974f1aa6d9e482e4fbd1901f1');
INSERT INTO "audit_log" VALUES(14,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000004','701ecf5f3a454ad4896d3cbfb7bf2a3bd571fa762be714cb685e7ecec6a1a40c','7860a4a8c1cb59db796827fc6c11fb1fab5e9318c279b397d773f46b77bbeb8e','9d5c5a8aea9f660eebf054312e21fce16038b6c974f1aa6d9e482e4fbd1901f1','6e204811e84424ebe79df224b8484ee73eb374ee2c1c7981ed8f120209eec000');
INSERT INTO "audit_log" VALUES(15,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000005','5ae24c9903ed16309283db32fb4416a5ee570a23be63aafdd76fdb6a8c7525db','5e8b27bb1120b18660eb8653fe1aca127233b8f191b984bf54c062a70a54d4e9','6e204811e84424ebe79df224b8484ee73eb374ee2c1c7981ed8f120209eec000','82a4863b570f7ce18a40626111655fd432752104bc9033c4eda6b03dc69573fb');
INSERT INTO "audit_log" VALUES(16,'2026-10-28T20:07:58.632516Z','alice','finding.risk_recalculate','finding','FND-000006','79af92ec3347a8638926cd3f7c0ab03882af4721913335ca15bfe528879133fa','14b1f151d02d0be4c87c16eb589058d6883ff0cd45f9053d8fab75feaa4a6156','82a4863b570f7ce18a40626111655fd432752104bc9033c4eda6b03dc69573fb','b48cd15a2bbd6b7dd0d4f2b28471d2713d653ed01429acd873c074abb332acc6');
INSERT INTO "audit_log" VALUES(17,'2026-10-28T20:07:59.098187Z','alice','task.create','task','TSK-000001',NULL,'6e8d1c21a5cada10b2a85f5b85594ca4ef8b505059f341781adbbee32d4cda5f','b48cd15a2bbd6b7dd0d4f2b28471d2713d653ed01429acd873c074abb332acc6','a4583f706f98bb417ad8a3cd3e51864d601780f4b5fa4c696cc3a02b99473dbf');
INSERT INTO "audit_log" VALUES(18,'2026-10-28T20:07:59.537780Z','alice','incident.create','incident','INC-000001',NULL,'9b032bdc1f930be9ff26e820c325bf1db4f78e4223700d9c2d267165c986e315','a4583f706f98bb417ad8a3cd3e51864d601780f4b5fa4c696cc3a02b99473dbf','849a5510123c12190b750e16ddc3e3dd50a33d05873a4c2bf27e65875cffc57f');
INSERT INTO "audit_log" VALUES(19,'2026-10-28T20:08:00.034368Z','alice','playbook.load','playbook','phishing-triage',NULL,'057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','849a5510123c12190b750e16ddc3e3dd50a33d05873a4c2bf27e65875cffc57f','880aaea7f9b01620adf6d1e4af7f3fcca8991d4bd60c097de9a621a64b212d5a');
INSERT INTO "audit_log" VALUES(20,'2026-10-28T20:08:00.481064Z','alice','playbook.attach','incident','INC-000001',NULL,'d699cf87594527cc31e2f50decd377c3c906f08330eaf35dff8cc9fac0fbaaa9','880aaea7f9b01620adf6d1e4af7f3fcca8991d4bd60c097de9a621a64b212d5a','620b350a6015251cabf9aed29c51f208ed37745c6607cc9ce7be9ab537f2ada6');
INSERT INTO "audit_log" VALUES(21,'2026-10-28T20:08:00.481064Z','alice','incident.playbook_attach','incident','INC-000001','9b032bdc1f930be9ff26e820c325bf1db4f78e4223700d9c2d267165c986e315','c5a7fc1d1472d504aa5d337c536d4f5f303d770bfbb2b09ab77c63cc193b761f','620b350a6015251cabf9aed29c51f208ed37745c6607cc9ce7be9ab537f2ada6','2772fa2f8690e6684d2e5585a878f3d4f76c12c02a7d129c4b3f787c25019134');
INSERT INTO "audit_log" VALUES(22,'2026-10-28T20:08:00.957012Z','alice','playbook.step_done','incident_step','INC-000001:step-001',NULL,'dcddab1dcfb655e76a111e8122411146bc3bb721cc84093a160820edbc3d44f9','2772fa2f8690e6684d2e5585a878f3d4f76c12c02a7d129c4b3f787c25019134','400c2c6cc01fffd27e205a32a684abe428a390ac3b4b72ba492ab458d93dccc9');
INSERT INTO "audit_log" VALUES(23,'2026-10-28T20:08:01.525325Z','alice','approval.request','approval','CHG-000001',NULL,'dfd0a1981d9bb56ebcc09a4abea4a6d4b94860a59bdc27417af068aa25c25f2f','400c2c6cc01fffd27e205a32a684abe428a390ac3b4b72ba492ab458d93dccc9','22d78e810c749695554153f94c13cda0325c83e5c76d58b4644339a8038bd903');
INSERT INTO "audit_log" VALUES(24,'2026-10-28T20:08:01.942384Z','bob','approval.approve','approval','CHG-000001','dfd0a1981d9bb56ebcc09a4abea4a6d4b94860a59bdc27417af068aa25c25f2f','41fa4b4ad689ed03e1b014dbe35e0e8c826cc1144d8a69c7649f4b0436669802','22d78e810c749695554153f94c13cda0325c83e5c76d58b4644339a8038bd903','134a08f57c6887afdca1c383c19ac27687a274d5a8619c7951cafe482ebc75c2');
INSERT INTO "audit_log" VALUES(25,'2026-10-28T20:08:02.347260Z','alice','playbook.step_done','incident_step','INC-000001:step-004',NULL,'3a1cde47226e84ef664f8055e9dbae167978392bda5ec4dbfe3c87e75ca6a4d6','134a08f57c6887afdca1c383c19ac27687a274d5a8619c7951cafe482ebc75c2','bc4ead7d84d33891c8d14ceff9f094338d4d996f7212e2993aaf44d13e6879ea');
INSERT INTO "audit_log" VALUES(26,'2026-10-28T20:08:02.347260Z','alice','approval.apply','approval','CHG-000001','057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','3a1cde47226e84ef664f8055e9dbae167978392bda5ec4dbfe3c87e75ca6a4d6','bc4ead7d84d33891c8d14ceff9f094338d4d996f7212e2993aaf44d13e6879ea','6107ca21836a715eafc51dfc6c231912d49cafac1d60f060f0c99c6eb12eb169');
CREATE TABLE counters (
    prefix TEXT PRIMARY KEY CHECK (prefix IN ('AST', 'FND', 'INC', 'TSK', 'PBK', 'CHG', 'RUN')),
    value INTEGER NOT NULL CHECK (value >= 0 AND value < 1000000000000)
) STRICT;
INSERT INTO "counters" VALUES('AST',1);
INSERT INTO "counters" VALUES('FND',6);
INSERT INTO "counters" VALUES('INC',1);
INSERT INTO "counters" VALUES('TSK',1);
INSERT INTO "counters" VALUES('PBK',0);
INSERT INTO "counters" VALUES('CHG',1);
INSERT INTO "counters" VALUES('RUN',3);
CREATE TABLE evidence (
    evidence_id INTEGER PRIMARY KEY,
    finding_id TEXT REFERENCES findings (finding_id) ON DELETE RESTRICT,
    incident_id TEXT REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    evidence_type TEXT NOT NULL CHECK ((evidence_type GLOB '[a-z]*' AND length(evidence_type) BETWEEN 2 AND 32 AND evidence_type NOT GLOB '*[^a-z0-9_-]*')),
    redacted_text TEXT NOT NULL CHECK (length(CAST(redacted_text AS BLOB)) BETWEEN 1 AND 4096),
    content_sha256 TEXT NOT NULL CHECK ((length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (finding_id IS NOT NULL OR incident_id IS NOT NULL)
) STRICT;
CREATE TABLE finding_occurrences (
    occurrence_id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings (finding_id) ON DELETE RESTRICT,
    import_run_id TEXT NOT NULL REFERENCES import_runs (run_id) ON DELETE RESTRICT,
    file_sha256 TEXT NOT NULL CHECK ((length(file_sha256) = 64 AND file_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_path TEXT NOT NULL CHECK (length(source_path) BETWEEN 1 AND 1024),
    location TEXT CHECK ((location IS NULL OR length(location) BETWEEN 1 AND 512)),
    observed_at TEXT NOT NULL CHECK (observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
) STRICT;
INSERT INTO "finding_occurrences" VALUES(1,'FND-000001','RUN-000001','7bdb69506325f77cee3ffdff7c2e53529f1c8a6401f8be2770351dcb36e556fe','scan.sarif','runs[0].results[0]','2026-10-28T20:07:57.233423Z');
INSERT INTO "finding_occurrences" VALUES(2,'FND-000002','RUN-000001','7bdb69506325f77cee3ffdff7c2e53529f1c8a6401f8be2770351dcb36e556fe','scan.sarif','runs[0].results[1]','2026-10-28T20:07:57.233423Z');
INSERT INTO "finding_occurrences" VALUES(3,'FND-000003','RUN-000002','afb94cca91119288fadfc28cf4c66032406505c85b0e30b9355bfdf13930f140','findings.json','items[0]','2026-10-28T20:07:57.693817Z');
INSERT INTO "finding_occurrences" VALUES(4,'FND-000004','RUN-000002','afb94cca91119288fadfc28cf4c66032406505c85b0e30b9355bfdf13930f140','findings.json','items[1]','2026-10-28T20:07:57.693817Z');
INSERT INTO "finding_occurrences" VALUES(5,'FND-000005','RUN-000003','f7bb5c1a082b8f35f5df54165d9fd0de9b62b14c69ae66b8c87d24f3a2afe567','findings.csv','row 2','2026-10-28T20:07:58.108479Z');
INSERT INTO "finding_occurrences" VALUES(6,'FND-000006','RUN-000003','f7bb5c1a082b8f35f5df54165d9fd0de9b62b14c69ae66b8c87d24f3a2afe567','findings.csv','row 3','2026-10-28T20:07:58.108479Z');
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY CHECK ((finding_id GLOB 'FND-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(finding_id) BETWEEN 10 AND 16 AND substr(finding_id, 5) NOT GLOB '*[^0-9]*')),
    fingerprint TEXT NOT NULL UNIQUE CHECK ((length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*')),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description TEXT NOT NULL CHECK (length(description) <= 8000),
    asset_id TEXT NOT NULL REFERENCES assets (asset_id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source IN ('sarif', 'generic_json', 'csv', 'manual')),
    evidence TEXT NOT NULL CHECK (length(CAST(evidence AS BLOB)) <= 4096),
    cvss_version TEXT CHECK (cvss_version IS NULL OR cvss_version = '4.0'),
    cvss_vector TEXT CHECK (cvss_vector IS NULL OR (cvss_vector GLOB 'CVSS:4.0/*' AND length(cvss_vector) <= 512)),
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)),
    cvss_score_source TEXT CHECK (cvss_score_source IS NULL OR cvss_score_source = 'imported'),
    technical_severity TEXT NOT NULL CHECK (technical_severity IN ('none', 'low', 'medium', 'high', 'critical')),
    business_priority TEXT CHECK ((business_priority IS NULL OR business_priority IN ('p1', 'p2', 'p3', 'p4'))),
    risk_factors TEXT NOT NULL CHECK (json_valid(risk_factors) AND json_type(risk_factors) = 'object'),
    risk_formula_version TEXT CHECK ((risk_formula_version IS NULL OR length(risk_formula_version) BETWEEN 1 AND 32)),
    risk_config_hash TEXT CHECK ((risk_config_hash IS NULL OR (length(risk_config_hash) = 64 AND risk_config_hash NOT GLOB '*[^0-9a-f]*'))),
    status TEXT NOT NULL CHECK (status IN ('open', 'triaged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),
    owner TEXT CHECK ((owner IS NULL OR length(owner) BETWEEN 1 AND 200)),
    sla_due_at TEXT CHECK ((sla_due_at IS NULL OR sla_due_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_seen TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (last_seen >= first_seen),
    CHECK (updated_at >= created_at),
    CHECK ((cvss_score IS NULL) = (cvss_score_source IS NULL)),
    CHECK (cvss_vector IS NULL OR cvss_version IS NOT NULL),
    CHECK (technical_severity <> 'none' OR cvss_score = 0.0)
) STRICT;
INSERT INTO "findings" VALUES('FND-000001','74aea075fc48f8540021c06759d4c0a737e8226671d1d3430cd956a5c6fd6bc9','SQL injection','user input flows into a query (reported by [EMPLOYEE])

Rule: Tainted data reaches a query','AST-000001','sarif','',NULL,NULL,NULL,NULL,'high','p1','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":100.0,"severity_points":60.0,"sla_hours":72.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open',NULL,'2026-10-31T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:58.632516Z');
INSERT INTO "findings" VALUES('FND-000002','f52aa0c60ecbd9935b2eaa1bf8151eb4c11ba2023b44a60e03b7fd58b87ec225','Hard-coded credential','found password=[REDACTED] in config

Rule: A credential is stored in source','AST-000001','sarif','',NULL,NULL,NULL,NULL,'medium','p2','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":62.79,"severity_points":35.0,"sla_hours":336.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open',NULL,'2026-11-11T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:57.233423Z','2026-10-28T20:07:58.632516Z');
INSERT INTO "findings" VALUES('FND-000003','bcbad6fbb3626a6ac144681a32304efa8cdde115b7ec1cdf41e18b2d406c7a45','Outdated TLS configuration','TLS 1.0 is still enabled','AST-000001','generic_json','cipher list: TLS_RSA_WITH_3DES',NULL,NULL,NULL,NULL,'medium','p2','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":62.79,"severity_points":35.0,"sla_hours":336.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open','platform','2026-11-11T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:58.632516Z');
INSERT INTO "findings" VALUES('FND-000004','e5f16130ad76135db611a3ece205908e045034d1158ca390de7f9a95c7f87d4b','Admin panel without MFA','No second factor on /admin','AST-000001','generic_json','token=[REDACTED]',NULL,NULL,NULL,NULL,'high','p1','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":100.0,"severity_points":60.0,"sla_hours":72.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open','platform','2026-10-31T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:57.693817Z','2026-10-28T20:07:58.632516Z');
INSERT INTO "findings" VALUES('FND-000005','45134e6fefc442ce789714560ae096fe0e7cc8282d69e19237b8431ec0ec959f','Weak password policy','Minimum length is 6','AST-000001','csv','policy export',NULL,NULL,NULL,NULL,'low','p4','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":26.91,"severity_points":15.0,"sla_hours":2160.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open',NULL,'2027-01-26T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.632516Z');
INSERT INTO "findings" VALUES('FND-000006','70851a48229e04d6f404cac1349f853b3daaeb3243027ef991b8b97507e84032','Open admin share','Share is readable by all staff','AST-000001','csv','api_key=[REDACTED]',NULL,NULL,NULL,NULL,'high','p1','{"criticality_weight":1.2,"data_weight":1.15,"environment_weight":1.0,"exposure_weight":1.3,"risk_score":100.0,"severity_points":60.0,"sla_hours":72.0}','risk-v1','15e2d1d6cd9586bf594f219315c5e83b13447c371959c1a39735dc49036283d3','open',NULL,'2026-10-31T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.108479Z','2026-10-28T20:07:58.632516Z');
CREATE TABLE import_runs (
    run_id TEXT PRIMARY KEY CHECK ((run_id GLOB 'RUN-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(run_id) BETWEEN 10 AND 16 AND substr(run_id, 5) NOT GLOB '*[^0-9]*')),
    source TEXT NOT NULL CHECK (source IN ('sarif', 'generic_json', 'csv', 'manual')),
    file_sha256 TEXT NOT NULL CHECK ((length(file_sha256) = 64 AND file_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_path TEXT NOT NULL CHECK (length(source_path) BETWEEN 1 AND 1024),
    imported_at TEXT NOT NULL CHECK (imported_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    record_count INTEGER NOT NULL CHECK (record_count >= 0)
) STRICT;
INSERT INTO "import_runs" VALUES('RUN-000001','sarif','7bdb69506325f77cee3ffdff7c2e53529f1c8a6401f8be2770351dcb36e556fe','scan.sarif','2026-10-28T20:07:57.233423Z',2);
INSERT INTO "import_runs" VALUES('RUN-000002','generic_json','afb94cca91119288fadfc28cf4c66032406505c85b0e30b9355bfdf13930f140','findings.json','2026-10-28T20:07:57.693817Z',2);
INSERT INTO "import_runs" VALUES('RUN-000003','csv','f7bb5c1a082b8f35f5df54165d9fd0de9b62b14c69ae66b8c87d24f3a2afe567','findings.csv','2026-10-28T20:07:58.108479Z',2);
CREATE TABLE incident_events (
    event_id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL CHECK (occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    actor TEXT NOT NULL CHECK ((actor GLOB '[a-z0-9]*' AND length(actor) BETWEEN 1 AND 128 AND actor NOT GLOB '*[^a-z0-9._@+-]*')),
    event_type TEXT NOT NULL CHECK ((event_type GLOB '[a-z]*' AND length(event_type) BETWEEN 2 AND 64 AND event_type NOT GLOB '*[^a-z0-9_.]*')),
    from_status TEXT CHECK ((from_status IS NULL OR from_status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed'))),
    to_status TEXT CHECK ((to_status IS NULL OR to_status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed')))
) STRICT;
INSERT INTO "incident_events" VALUES(1,'INC-000001','2026-10-28T20:07:59.537780Z','alice','incident_created',NULL,'new');
INSERT INTO "incident_events" VALUES(2,'INC-000001','2026-10-28T20:08:00.481064Z','alice','playbook_attached',NULL,NULL);
INSERT INTO "incident_events" VALUES(3,'INC-000001','2026-10-28T20:08:00.957012Z','alice','playbook_step_done',NULL,NULL);
INSERT INTO "incident_events" VALUES(4,'INC-000001','2026-10-28T20:08:02.347260Z','alice','playbook_step_done',NULL,NULL);
CREATE TABLE incident_links (
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL REFERENCES findings (finding_id) ON DELETE RESTRICT,
    linked_at TEXT NOT NULL CHECK (linked_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (incident_id, finding_id)
) STRICT;
CREATE TABLE incident_notes (
    note_id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    author TEXT NOT NULL CHECK ((author GLOB '[a-z0-9]*' AND length(author) BETWEEN 1 AND 128 AND author NOT GLOB '*[^a-z0-9._@+-]*')),
    redacted_body TEXT NOT NULL CHECK (length(redacted_body) BETWEEN 1 AND 8000)
) STRICT;
CREATE TABLE incident_playbook_steps (
    incident_id TEXT NOT NULL REFERENCES incident_playbooks (incident_id) ON DELETE RESTRICT,
    step_id TEXT NOT NULL CHECK ((step_id GLOB '[a-z]*' AND length(step_id) BETWEEN 2 AND 64 AND step_id NOT GLOB '*[^a-z0-9_-]*')),
    completed_at TEXT NOT NULL CHECK (completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    completed_by TEXT NOT NULL CHECK ((completed_by GLOB '[a-z0-9]*' AND length(completed_by) BETWEEN 1 AND 128 AND completed_by NOT GLOB '*[^a-z0-9._@+-]*')),
    change_id TEXT REFERENCES pending_changes (change_id) ON DELETE RESTRICT,
    PRIMARY KEY (incident_id, step_id)
) STRICT;
INSERT INTO "incident_playbook_steps" VALUES('INC-000001','step-001','2026-10-28T20:08:00.957012Z','alice',NULL);
INSERT INTO "incident_playbook_steps" VALUES('INC-000001','step-004','2026-10-28T20:08:02.347260Z','alice','CHG-000001');
CREATE TABLE incident_playbooks (
    incident_id TEXT PRIMARY KEY REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    playbook_id TEXT NOT NULL,
    version TEXT NOT NULL,
    config_hash TEXT NOT NULL CHECK ((config_hash NOT GLOB '*[^0-9a-f]*' AND length(config_hash) = 64)),
    attached_at TEXT NOT NULL CHECK (attached_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    attached_by TEXT NOT NULL CHECK ((attached_by GLOB '[a-z0-9]*' AND length(attached_by) BETWEEN 1 AND 128 AND attached_by NOT GLOB '*[^a-z0-9._@+-]*')),
    FOREIGN KEY (playbook_id, version) REFERENCES playbook_versions (playbook_id, version) ON DELETE RESTRICT
) STRICT;
INSERT INTO "incident_playbooks" VALUES('INC-000001','phishing-triage','1.0','057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','2026-10-28T20:08:00.481064Z','alice');
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY CHECK ((incident_id GLOB 'INC-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(incident_id) BETWEEN 10 AND 16 AND substr(incident_id, 5) NOT GLOB '*[^0-9]*')),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed')),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    summary TEXT NOT NULL CHECK (length(summary) <= 8000),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    closed_at TEXT CHECK ((closed_at IS NULL OR closed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    playbook_id TEXT REFERENCES playbooks (playbook_id) ON DELETE RESTRICT,
    closure_reason TEXT CHECK ((closure_reason IS NULL OR length(closure_reason) BETWEEN 1 AND 500)),
    CHECK (updated_at >= created_at),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((status = 'closed') = (closure_reason IS NOT NULL)),
    CHECK (closed_at IS NULL OR closed_at >= created_at)
) STRICT;
INSERT INTO "incidents" VALUES('INC-000001','Phish campaign','high','new','ir','','2026-10-28T20:07:59.537780Z','2026-10-28T20:08:00.481064Z',NULL,'phishing-triage',NULL);
CREATE TABLE pending_changes (
    change_id TEXT PRIMARY KEY CHECK ((change_id GLOB 'CHG-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(change_id) BETWEEN 10 AND 16 AND substr(change_id, 5) NOT GLOB '*[^0-9]*')),
    object_type TEXT NOT NULL CHECK ((object_type GLOB '[a-z]*' AND length(object_type) BETWEEN 2 AND 64 AND object_type NOT GLOB '*[^a-z0-9_-]*')),
    object_id TEXT NOT NULL CHECK ((length(object_id) BETWEEN 1 AND 64 AND object_id NOT GLOB '*[^A-Za-z0-9._:-]*')),
    requester TEXT NOT NULL CHECK ((requester GLOB '[a-z0-9]*' AND length(requester) BETWEEN 1 AND 128 AND requester NOT GLOB '*[^a-z0-9._@+-]*')),
    approver TEXT CHECK (approver IS NULL OR (approver GLOB '[a-z0-9]*' AND length(approver) BETWEEN 1 AND 128 AND approver NOT GLOB '*[^a-z0-9._@+-]*')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    before_hash TEXT CHECK ((before_hash IS NULL OR (length(before_hash) = 64 AND before_hash NOT GLOB '*[^0-9a-f]*'))),
    proposed_after_hash TEXT NOT NULL CHECK ((length(proposed_after_hash) = 64 AND proposed_after_hash NOT GLOB '*[^0-9a-f]*')),
    requested_at TEXT NOT NULL CHECK (requested_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    decided_at TEXT CHECK ((decided_at IS NULL OR decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    require_distinct_approver INTEGER NOT NULL DEFAULT 1 CHECK (require_distinct_approver IN (0, 1)),
    CHECK (expires_at > requested_at),
    CHECK ((status IN ('approved', 'rejected')) = (decided_at IS NOT NULL)),
    CHECK ((status IN ('approved', 'rejected')) = (approver IS NOT NULL)),
    CHECK (decided_at IS NULL OR decided_at >= requested_at),
    CHECK (require_distinct_approver = 0 OR approver IS NULL OR approver <> requester)
) STRICT;
INSERT INTO "pending_changes" VALUES('CHG-000001','incident_step','INC-000001:step-004','alice','bob','approved','block','057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','1f0b250ee4160dd4c6af1b33b126f341a0d0fa6914cb43b848f6f59d78350afa','2026-10-28T20:08:01.525325Z','2026-11-04T20:08:01.525325Z','2026-10-28T20:08:01.942384Z',1);
CREATE TABLE playbook_versions (
    playbook_id TEXT NOT NULL REFERENCES playbooks (playbook_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK ((length(version) BETWEEN 1 AND 32 AND version NOT GLOB '*[^0-9A-Za-z._-]*')),
    definition TEXT NOT NULL CHECK (json_valid(definition) AND json_type(definition) = 'object'),
    config_hash TEXT NOT NULL CHECK ((config_hash NOT GLOB '*[^0-9a-f]*' AND length(config_hash) = 64)),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (playbook_id, version)
) STRICT;
INSERT INTO "playbook_versions" VALUES('phishing-triage','1.0','{"closure_criteria":["Mailbox cleaned"],"config_hash":"057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9","escalation_criteria":["Credentials were entered"],"incident_types":["phishing"],"name":"Phishing triage","playbook_id":"phishing-triage","roles":["analyst","lead"],"steps":[{"items":[],"owner_role":"analyst","potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-001","step_type":"manual","text":"Read the reported message headers and confirm it is phishing.","title":"Confirm the report"},{"items":["Sender address recorded","Links recorded"],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-002","step_type":"checklist","text":"","title":"Collect indicators"},{"items":[],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-003","step_type":"notify_text","text":"Team, a phishing campaign was confirmed. Do not open the message.","title":"Notify the team"},{"items":[],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":true,"step_id":"step-004","step_type":"manual","text":"Ask the mail admin to block the sender domain.","title":"Block the sender domain"}],"version":"1.0"}','057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','2026-10-28T20:08:00.034368Z');
CREATE TABLE playbooks (
    playbook_id TEXT PRIMARY KEY CHECK ((playbook_id GLOB '[a-z]*' AND length(playbook_id) BETWEEN 2 AND 64 AND playbook_id NOT GLOB '*[^a-z0-9_-]*')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 32),
    definition TEXT NOT NULL CHECK (json_valid(definition) AND json_type(definition) = 'object'),
    config_hash TEXT NOT NULL CHECK ((length(config_hash) = 64 AND config_hash NOT GLOB '*[^0-9a-f]*')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (updated_at >= created_at)
) STRICT;
INSERT INTO "playbooks" VALUES('phishing-triage','Phishing triage','1.0','{"closure_criteria":["Mailbox cleaned"],"config_hash":"057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9","escalation_criteria":["Credentials were entered"],"incident_types":["phishing"],"name":"Phishing triage","playbook_id":"phishing-triage","roles":["analyst","lead"],"steps":[{"items":[],"owner_role":"analyst","potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-001","step_type":"manual","text":"Read the reported message headers and confirm it is phishing.","title":"Confirm the report"},{"items":["Sender address recorded","Links recorded"],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-002","step_type":"checklist","text":"","title":"Collect indicators"},{"items":[],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":false,"step_id":"step-003","step_type":"notify_text","text":"Team, a phishing campaign was confirmed. Do not open the message.","title":"Notify the team"},{"items":[],"owner_role":null,"potentially_destructive":false,"requires_manual_approval":true,"step_id":"step-004","step_type":"manual","text":"Ask the mail admin to block the sender domain.","title":"Block the sender domain"}],"version":"1.0"}','057e1b5dc0bf31693e4e46ec9afc9ded446ffbb1eb66cdf72f7c70b2dcfd61b9','2026-10-28T20:08:00.034368Z','2026-10-28T20:08:00.034368Z');
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    checksum TEXT NOT NULL CHECK ((length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*')),
    applied_at TEXT NOT NULL CHECK (applied_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
) STRICT;
INSERT INTO "schema_version" VALUES(1,'initial_schema','d7c8ce7fa4af8f2b27925f95c0f10e5f87b6257d59c063096d48ec67346bea61','2026-10-28T20:07:56.782189Z');
INSERT INTO "schema_version" VALUES(2,'playbook_runs','76b5ee60b77c7dee73bc4105eb3f0a15917fce46510eebe1752d73860878ce62','2026-10-28T20:07:56.782189Z');
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY CHECK ((task_id GLOB 'TSK-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(task_id) BETWEEN 10 AND 16 AND substr(task_id, 5) NOT GLOB '*[^0-9]*')),
    finding_id TEXT REFERENCES findings (finding_id) ON DELETE RESTRICT,
    incident_id TEXT REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    due_at TEXT CHECK ((due_at IS NULL OR due_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    completed_at TEXT CHECK ((completed_at IS NULL OR completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    CHECK (finding_id IS NOT NULL OR incident_id IS NOT NULL),
    CHECK ((status = 'done') = (completed_at IS NOT NULL)),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT;
INSERT INTO "tasks" VALUES('TSK-000001','FND-000001',NULL,'Fix SQLi','dev',NULL,'open','2026-10-28T20:07:59.098187Z','2026-10-28T20:07:59.098187Z',NULL);
CREATE INDEX findings_asset_id ON findings (asset_id);
CREATE INDEX findings_status ON findings (status);
CREATE UNIQUE INDEX finding_occurrences_unique ON finding_occurrences (finding_id, import_run_id, source_path, COALESCE(location, ''));
CREATE INDEX pending_changes_status ON pending_changes (status, expires_at);
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log sequence must be consecutive')
    WHERE NEW.seq <> COALESCE((SELECT MAX(seq) FROM audit_log), 0) + 1;
    SELECT RAISE(ABORT, 'audit_log prev_hash must link to the previous entry')
    WHERE NEW.prev_hash <> COALESCE((SELECT entry_hash FROM audit_log WHERE seq = NEW.seq - 1), '0000000000000000000000000000000000000000000000000000000000000000');
END;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER playbook_versions_no_update BEFORE UPDATE ON playbook_versions
BEGIN
    SELECT RAISE(ABORT, 'playbook versions are immutable');
END;
CREATE TRIGGER playbook_versions_no_delete BEFORE DELETE ON playbook_versions
BEGIN
    SELECT RAISE(ABORT, 'playbook versions are immutable');
END;
CREATE TRIGGER incident_playbooks_no_update BEFORE UPDATE ON incident_playbooks
BEGIN
    SELECT RAISE(ABORT, 'a playbook attachment is immutable');
END;
CREATE TRIGGER incident_playbooks_no_delete BEFORE DELETE ON incident_playbooks
BEGIN
    SELECT RAISE(ABORT, 'a playbook attachment is immutable');
END;
CREATE TRIGGER incident_playbook_steps_no_update BEFORE UPDATE ON incident_playbook_steps
BEGIN
    SELECT RAISE(ABORT, 'a completed step cannot be changed');
END;
CREATE TRIGGER incident_playbook_steps_no_delete BEFORE DELETE ON incident_playbook_steps
BEGIN
    SELECT RAISE(ABORT, 'a completed step cannot be changed');
END;
COMMIT;
