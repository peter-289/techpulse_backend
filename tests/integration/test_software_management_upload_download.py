from app.main import app

def test_software_management_contract_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app}

    assert "/api/v1/software-management" in paths
    assert "/api/v1/software-management/upload" in paths
    assert "/api/v1/software-management/{software_id}/versions" in paths
    assert "/api/v1/software-management/{software_id}/versions/upload" in paths
    assert "/api/v1/software-management/{software_id}/versions/{version}/artifacts" in paths
    assert "/api/v1/software-management/{software_id}/versions/{version}/artifacts/{artifact_id}/download" in paths
    assert "/api/v1/software-management/{software_id}/versions/{version}/download" in paths
    assert "/api/v1/software-management/{software_id}/pricing" in paths
    assert "/api/v1/software-management/summary" in paths
    assert "/api/v1/admin/software/packages" in paths
    assert "/api/v1/admin/software/summary" in paths

if __name__ == "__main__":
    test_software_management_contract_routes_are_registered()
