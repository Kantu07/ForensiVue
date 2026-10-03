import pytest
import os
from fastapi.testclient import TestClient
from forensivue.api.main import app

client = TestClient(app)

def test_api_images():
    response = client.get("/api/images")
    assert response.status_code == 200
    data = response.json()
    assert "images" in data

def test_api_identify():
    # Make sure we have a test image
    img = "generated/normal.dd"
    if not os.path.exists(img):
        pytest.skip("normal.dd not found")
        
    response = client.post("/api/pipeline/identify", json={"image_path": img})
    assert response.status_code == 200
    data = response.json()
    assert "hashes" in data
    assert "identification" in data
    assert "recordings" in data

def test_api_recover():
    img = "generated/deleted.dd"
    if not os.path.exists(img):
        pytest.skip("deleted.dd not found")
        
    response = client.post("/api/pipeline/recover", json={"image_path": img})
    assert response.status_code == 200
    data = response.json()
    assert "recovered" in data

def test_api_timeline():
    img = "generated/multi_channel.dd"
    if not os.path.exists(img):
        pytest.skip("multi_channel.dd not found")
        
    response = client.post("/api/pipeline/timeline", json={"image_path": img})
    assert response.status_code == 200
    data = response.json()
    assert "timeline" in data

def test_api_report():
    img = "generated/mixed.dd"
    if not os.path.exists(img):
        pytest.skip("mixed.dd not found")
        
    req = {
        "image_path": img,
        "case_id": "API-TEST",
        "examiner": "Jane API"
    }
    response = client.post("/api/pipeline/report", json=req)
    assert response.status_code == 200
    data = response.json()
    assert "pdf_url" in data
    assert "html_url" in data

def test_api_custody():
    res1 = client.get("/api/custody/log")
    assert res1.status_code == 200
    assert "log" in res1.json()
    
    res2 = client.get("/api/custody/verify")
    assert res2.status_code == 200
    assert "valid" in res2.json()
