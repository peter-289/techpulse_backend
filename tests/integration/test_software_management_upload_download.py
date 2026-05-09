from app.main import app


def test_software_management_contract_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.routes}

    assert "/api/v1/software-management" in paths
    assert "/api/v1/software-management/upload" in paths
    assert "/api/v1/software-management/{software_id}/versions" in paths
    assert "/api/v1/software-management/{software_id}/versions/upload" in paths
    assert "/api/v1/software-management/{software_id}/versions/{version}/download" in paths
    assert "/api/v1/software-management/{software_id}/pricing" in paths
    assert "/api/v1/software-management/{software_id}/checkout" in paths
    assert "/api/v1/software-management/payments/{payment_id}/confirm" in paths
    assert "/api/v1/software-management/admin/packages" in paths
    assert "/api/v1/software-management/admin/summary" in paths
