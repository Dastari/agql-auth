#[test]
fn host_can_use_explicit_graphql_features() {
    assert!(
        !async_graphql::http::GraphiQLSource::build()
            .endpoint("/graphql")
            .finish()
            .is_empty()
    );
    assert!(
        !async_graphql::http::playground_source(async_graphql::http::GraphQLPlaygroundConfig::new(
            "/graphql"
        ))
        .is_empty()
    );
    let _builder = async_graphql::dynamic::Schema::build("Query", None, None);
    // Compile-check the file-backed upload representation without creating a file.
    fn upload(file: std::fs::File) -> async_graphql::UploadValue {
        async_graphql::UploadValue {
            filename: "fixture".into(),
            content_type: None,
            content: file,
        }
    }
    let _constructor: fn(std::fs::File) -> async_graphql::UploadValue = upload;
}
