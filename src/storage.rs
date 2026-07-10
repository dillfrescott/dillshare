use axum::body::Body;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub enum Storage {
    S3(aws_sdk_s3::Client),
    Memory(Arc<Mutex<MemoryBackend>>),
}

#[derive(Default)]
pub struct MemoryBackend {
    pub files: HashMap<String, Vec<u8>>,
    pub content_types: HashMap<String, String>,
    pub multipart_uploads: HashMap<String, HashMap<i32, Vec<u8>>>,
}

pub struct GetObjectOutput {
    pub body: Body,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    pub last_modified_secs: i64,
}

#[derive(Debug, Clone)]
pub struct CompletedPart {
    pub e_tag: String,
    pub part_number: i32,
}

impl Storage {
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        range_header: Option<String>,
    ) -> Result<GetObjectOutput, String> {
        match self {
            Storage::S3(client) => {
                let mut req = client.get_object().bucket(bucket).key(key);
                if let Some(r) = range_header {
                    req = req.range(r);
                }
                match req.send().await {
                    Ok(res) => {
                        let ct = res.content_type.clone();
                        let cl = res.content_length;
                        let stream = tokio_util::io::ReaderStream::new(res.body.into_async_read());
                        Ok(GetObjectOutput {
                            body: Body::from_stream(stream),
                            content_type: ct,
                            content_length: cl.map(|v| v as u64),
                        })
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                if let Some(data) = m.files.get(key) {
                    let mut start = 0;
                    let mut end = data.len();
                    if let Some(r) = range_header {
                        if let Some(r_str) = r.strip_prefix("bytes=") {
                            let mut parts = r_str.split('-');
                            if let Some(s) = parts.next() {
                                start = s.parse().unwrap_or(0);
                            }
                            if let Some(e) = parts.next() {
                                if !e.is_empty() {
                                    end = e.parse::<usize>().unwrap_or(data.len() - 1) + 1;
                                }
                            }
                        }
                    }
                    let slice = data[start.min(data.len())..end.min(data.len())].to_vec();
                    Ok(GetObjectOutput {
                        body: Body::from(slice),
                        content_type: m.content_types.get(key).cloned(),
                        content_length: Some(data.len() as u64),
                    })
                } else {
                    Err("Not found".to_string())
                }
            }
        }
    }

    pub async fn get_object_bytes(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        match self {
            Storage::S3(client) => {
                let res = client
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                let bytes = res
                    .body
                    .collect()
                    .await
                    .map_err(|e| e.to_string())?
                    .into_bytes();
                Ok(bytes.to_vec())
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                m.files
                    .get(key)
                    .cloned()
                    .ok_or_else(|| "Not found".to_string())
            }
        }
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Storage::S3(client) => {
                let mut req = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data));
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                req.send().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                m.files.insert(key.to_string(), data);
                if let Some(ct) = content_type {
                    m.content_types.insert(key.to_string(), ct.to_string());
                }
                Ok(())
            }
        }
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<bool, String> {
        match self {
            Storage::S3(client) => {
                match client.head_object().bucket(bucket).key(key).send().await {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.files.contains_key(key))
            }
        }
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), String> {
        match self {
            Storage::S3(client) => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                m.files.remove(key);
                m.content_types.remove(key);
                Ok(())
            }
        }
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: Option<i32>,
    ) -> Result<Vec<ObjectInfo>, String> {
        match self {
            Storage::S3(client) => {
                let mut req = client.list_objects_v2().bucket(bucket);
                if let Some(p) = prefix {
                    req = req.prefix(p);
                }
                if let Some(mk) = max_keys {
                    req = req.max_keys(mk);
                }
                let mut keys = Vec::new();
                let mut response = req.into_paginator().send();
                while let Some(res) = response.next().await {
                    if let Ok(page) = res {
                        for obj in page.contents() {
                            if let Some(k) = obj.key() {
                                keys.push(ObjectInfo {
                                    key: k.to_string(),
                                    size: obj.size().unwrap_or(0),
                                    last_modified_secs: obj
                                        .last_modified()
                                        .map(|d| d.secs())
                                        .unwrap_or(0),
                                });
                            }
                        }
                    } else {
                        return Err("S3 list error".to_string());
                    }
                }
                Ok(keys)
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                let mut keys = Vec::new();
                for (k, v) in &m.files {
                    if let Some(p) = prefix {
                        if !k.starts_with(p) {
                            continue;
                        }
                    }
                    keys.push(ObjectInfo {
                        key: k.clone(),
                        size: v.len() as i64,
                        last_modified_secs: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                    });
                    if let Some(mk) = max_keys {
                        if keys.len() as i32 >= mk {
                            break;
                        }
                    }
                }
                Ok(keys)
            }
        }
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
    ) -> Result<String, String> {
        match self {
            Storage::S3(client) => {
                let mut req = client.create_multipart_upload().bucket(bucket).key(key);
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                let res = req.send().await.map_err(|e| e.to_string())?;
                Ok(res.upload_id().unwrap_or_default().to_string())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                let upload_id = uuid::Uuid::new_v4().to_string();
                m.multipart_uploads
                    .insert(upload_id.clone(), HashMap::new());
                Ok(upload_id)
            }
        }
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Vec<u8>,
    ) -> Result<String, String> {
        match self {
            Storage::S3(client) => {
                let res = client
                    .upload_part()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data))
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(res.e_tag().unwrap_or_default().to_string())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                if let Some(upload) = m.multipart_uploads.get_mut(upload_id) {
                    upload.insert(part_number, data);
                    Ok("mem-etag".to_string())
                } else {
                    Err("Upload ID not found".to_string())
                }
            }
        }
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), String> {
        match self {
            Storage::S3(client) => {
                let mut builder = aws_sdk_s3::types::CompletedMultipartUpload::builder();
                for p in parts {
                    builder = builder.parts(
                        aws_sdk_s3::types::CompletedPart::builder()
                            .part_number(p.part_number)
                            .e_tag(p.e_tag)
                            .build(),
                    );
                }
                client
                    .complete_multipart_upload()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .multipart_upload(builder.build())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                if let Some(upload) = m.multipart_uploads.remove(upload_id) {
                    let mut data = Vec::new();
                    let mut sorted_parts: Vec<_> = upload.into_iter().collect();
                    sorted_parts.sort_by_key(|(k, _)| *k);
                    for (_, part_data) in sorted_parts {
                        data.extend(part_data);
                    }
                    m.files.insert(key.to_string(), data);
                    Ok(())
                } else {
                    Err("Upload ID not found".to_string())
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), String> {
        match self {
            Storage::S3(client) => {
                client
                    .abort_multipart_upload()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                m.multipart_uploads.remove(upload_id);
                Ok(())
            }
        }
    }
}
