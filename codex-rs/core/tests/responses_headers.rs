use std::sync::Arc;

use codex_app_server_protocol::AuthMode;
use codex_core::AuthManager;
use codex_core::CodexAuth;
use codex_core::ContentItem;
use codex_core::ModelClient;
use codex_core::ModelProviderInfo;
use codex_core::Prompt;
use codex_core::ResponseEvent;
use codex_core::ResponseItem;
use codex_core::WireApi;
use codex_core::models_manager::manager::ModelsManager;
use codex_otel::otel_manager::OtelManager;
use codex_protocol::ConversationId;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use core_test_support::load_default_config_for_test;
use core_test_support::responses;
use futures::StreamExt;
use tempfile::TempDir;
use wiremock::matchers::header;

// New imports for the unit test
use codex_api::provider::{Provider, RetryConfig};
use codex_api::requests::responses::ResponsesRequestBuilder;
use http::HeaderMap;
use std::time::Duration;
use serde_json::Value;

#[tokio::test]
async fn responses_stream_includes_subagent_header_on_review() {
    core_test_support::skip_if_no_network!();

    let server = responses::start_mock_server().await;
    let response_body = responses::sse(vec![
        responses::ev_response_created("resp-1"),
        responses::ev_completed("resp-1"),
    ]);

    let request_recorder = responses::mount_sse_once_match(
        &server,
        header("x-openai-subagent", "review"),
        response_body,
    )
    .await;

    let provider = ModelProviderInfo {
        name: "mock".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        env_key: None,
        env_key_instructions: None,
        experimental_bearer_token: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        request_max_retries: Some(0),
        stream_max_retries: Some(0),
        stream_idle_timeout_ms: Some(5_000),
        requires_openai_auth: false,
    };

    let codex_home = TempDir::new().expect("failed to create TempDir");
    let mut config = load_default_config_for_test(&codex_home).await;
    config.model_provider_id = provider.name.clone();
    config.model_provider = provider.clone();
    let effort = config.model_reasoning_effort;
    let summary = config.model_reasoning_summary;
    let model = ModelsManager::get_model_offline(config.model.as_deref());
    config.model = Some(model.clone());
    let config = Arc::new(config);

    let conversation_id = ConversationId::new();
    let auth_mode = AuthMode::ChatGPT;
    let session_source = SessionSource::SubAgent(SubAgentSource::Review);
    let model_family = ModelsManager::construct_model_family_offline(model.as_str(), &config);
    let otel_manager = OtelManager::new(
        conversation_id,
        model.as_str(),
        model_family.slug.as_str(),
        None,
        Some("test@test.com".to_string()),
        Some(auth_mode),
        false,
        "test".to_string(),
        session_source.clone(),
    );

    let client = ModelClient::new(
        Arc::clone(&config),
        None,
        model_family,
        otel_manager,
        provider,
        effort,
        summary,
        conversation_id.clone(),
        conversation_id.clone(),
        session_source,
    );

    let mut prompt = Prompt::default();
    prompt.input = vec![ResponseItem::Message {
        id: None,
        role: "user".into(),
        content: vec![ContentItem::InputText {
            text: "hello".into(),
        }],
    }];

    let mut stream = client.stream(&prompt).await.expect("stream failed");
    while let Some(event) = stream.next().await {
        if matches!(event, Ok(ResponseEvent::Completed { .. })) {
            break;
        }
    }

    let request = request_recorder.single_request();
    assert_eq!(
        request.header("x-openai-subagent").as_deref(),
        Some("review")
    );
}

#[tokio::test]
async fn responses_stream_includes_subagent_header_on_other() {
    core_test_support::skip_if_no_network!();

    let server = responses::start_mock_server().await;
    let response_body = responses::sse(vec![
        responses::ev_response_created("resp-1"),
        responses::ev_completed("resp-1"),
    ]);

    let request_recorder = responses::mount_sse_once_match(
        &server,
        header("x-openai-subagent", "my-task"),
        response_body,
    )
    .await;

    let provider = ModelProviderInfo {
        name: "mock".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        env_key: None,
        env_key_instructions: None,
        experimental_bearer_token: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        request_max_retries: Some(0),
        stream_max_retries: Some(0),
        stream_idle_timeout_ms: Some(5_000),
        requires_openai_auth: false,
    };

    let codex_home = TempDir::new().expect("failed to create TempDir");
    let mut config = load_default_config_for_test(&codex_home).await;
    config.model_provider_id = provider.name.clone();
    config.model_provider = provider.clone();
    let effort = config.model_reasoning_effort;
    let summary = config.model_reasoning_summary;
    let model = ModelsManager::get_model_offline(config.model.as_deref());
    config.model = Some(model.clone());
    let config = Arc::new(config);

    let conversation_id = ConversationId::new();
    let auth_mode = AuthMode::ChatGPT;
    let session_source = SessionSource::SubAgent(SubAgentSource::Other("my-task".to_string()));
    let model_family = ModelsManager::construct_model_family_offline(model.as_str(), &config);

    let otel_manager = OtelManager::new(
        conversation_id,
        model.as_str(),
        model_family.slug.as_str(),
        None,
        Some("test@test.com".to_string()),
        Some(auth_mode),
        false,
        "test".to_string(),
        session_source.clone(),
    );

    let client = ModelClient::new(
        Arc::clone(&config),
        None,
        model_family,
        otel_manager,
        provider,
        effort,
        summary,
        conversation_id.clone(),
        conversation_id.clone(),
        session_source,
    );

    let mut prompt = Prompt::default();
    prompt.input = vec![ResponseItem::Message {
        id: None,
        role: "user".into(),
        content: vec![ContentItem::InputText {
            text: "hello".into(),
        }],
    }];

    let mut stream = client.stream(&prompt).await.expect("stream failed");
    while let Some(event) = stream.next().await {
        if matches!(event, Ok(ResponseEvent::Completed { .. })) {
            break;
        }
    }

    let request = request_recorder.single_request();
    assert_eq!(
        request.header("x-openai-subagent").as_deref(),
        Some("my-task")
    );
}

#[tokio::test]
async fn responses_respects_model_family_overrides_from_config() {
    core_test_support::skip_if_no_network!();

    let server = responses::start_mock_server().await;
    let response_body = responses::sse(vec![
        responses::ev_response_created("resp-1"),
        responses::ev_completed("resp-1"),
    ]);

    let request_recorder = responses::mount_sse_once(&server, response_body).await;

    let provider = ModelProviderInfo {
        name: "mock".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        env_key: None,
        env_key_instructions: None,
        experimental_bearer_token: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        request_max_retries: Some(0),
        stream_max_retries: Some(0),
        stream_idle_timeout_ms: Some(5_000),
        requires_openai_auth: false,
    };

    let codex_home = TempDir::new().expect("failed to create TempDir");
    let mut config = load_default_config_for_test(&codex_home).await;
    config.model = Some("gpt-3.5-turbo".to_string());
    config.model_provider_id = provider.name.clone();
    config.model_provider = provider.clone();
    config.model_supports_reasoning_summaries = Some(true);
    config.model_reasoning_summary = ReasoningSummary::Detailed;
    let effort = config.model_reasoning_effort;
    let summary = config.model_reasoning_summary;
    let model = config.model.clone().expect("model configured");
    let config = Arc::new(config);

    let conversation_id = ConversationId::new();
    let auth_mode =
        AuthManager::from_auth_for_testing(CodexAuth::from_api_key("Test API Key")).get_auth_mode();
    let session_source =
        SessionSource::SubAgent(SubAgentSource::Other("override-check".to_string()));
    let model_family = ModelsManager::construct_model_family_offline(model.as_str(), &config);
    let otel_manager = OtelManager::new(
        conversation_id,
        model.as_str(),
        model_family.slug.as_str(),
        None,
        Some("test@test.com".to_string()),
        auth_mode,
        false,
        "test".to_string(),
        session_source.clone(),
    );

    let client = ModelClient::new(
        Arc::clone(&config),
        None,
        model_family,
        otel_manager,
        provider,
        effort,
        summary,
        conversation_id.clone(),
        conversation_id.clone(),
        session_source,
    );

    let mut prompt = Prompt::default();
    prompt.input = vec![ResponseItem::Message {
        id: None,
        role: "user".into(),
        content: vec![ContentItem::InputText {
            text: "hello".into(),
        }],
    }];

    let mut stream = client.stream(&prompt).await.expect("stream failed");
    while let Some(event) = stream.next().await {
        if matches!(event, Ok(ResponseEvent::Completed { .. })) {
            break;
        }
    }

    let request = request_recorder.single_request();
    let body = request.body_json();
    let reasoning = body
        .get("reasoning")
        .and_then(|value| value.as_object())
        .cloned();

    assert!(
        reasoning.is_some(),
        "reasoning should be present when config enables summaries"
    );

    assert_eq!(
        reasoning
            .as_ref()
            .and_then(|value| value.get("summary"))
            .and_then(|value| value.as_str()),
        Some("detailed")
    );
}

// New helper and test for wire_session_id verification
fn make_provider() -> Provider {
    Provider {
        name: "test".to_string(),
        base_url: "http://localhost".to_string(),
        query_params: None,
        wire: codex_api::provider::WireApi::Responses,
        headers: HeaderMap::new(),
        retry: RetryConfig {
            max_attempts: 1,
            base_delay: Duration::from_millis(10),
            retry_429: false,
            retry_5xx: false,
            retry_transport: false,
        },
        stream_idle_timeout: Duration::from_secs(10),
    }
}

#[test]
fn sends_wire_session_id_in_headers_but_cache_key_in_body() {
    let provider = make_provider();
    let conversation_id = "conv-1";
    let wire_session_id = "conv-orig";

    // Use codex_protocol types directly for the unit test
    let prompt = vec![codex_protocol::models::ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![codex_protocol::models::ContentItem::OutputText { text: "hi".into() }],
    }];

    let req = ResponsesRequestBuilder::new("gpt-4o", "inst", &prompt)
        .prompt_cache_key(Some(conversation_id.to_string()))
        .conversation(Some(wire_session_id.to_string()))
        .build(&provider)
        .expect("build request");

    // Verify Headers
    let h = &req.headers;
    assert_eq!(h.get("conversation_id").unwrap().to_str().unwrap(), wire_session_id);
    assert_eq!(h.get("session_id").unwrap().to_str().unwrap(), wire_session_id);

    // Verify Extra Header
    let extra = h.get("extra").expect("extra header");
    let extra_json: Value = serde_json::from_slice(extra.as_bytes()).expect("parse extra");
    assert_eq!(extra_json["session_id"], wire_session_id);

    // Verify Body
    let body = req.body;
    assert_eq!(body["prompt_cache_key"], conversation_id);
}
