import yaml

from sqli.dao.student import Student

from tests.helpers import BCRYPT_HASH, PASSWORD, FakeConn, FakeCursor, make_user, run


def test_student_name_is_passed_as_parameter():
    cur = FakeCursor()
    payload = "Robert'); DROP TABLE students; --"
    run(Student.create(FakeConn(cur), payload))
    query, params = cur.calls[0]
    assert payload not in query
    assert params == {"name": payload}


def test_password_is_verified_with_bcrypt():
    assert make_user(BCRYPT_HASH).check_password(PASSWORD) is True


def test_redis_service_is_hardened():
    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)
    redis = compose["services"]["redis"]
    assert redis.get("read_only") is True
    assert "no-new-privileges:true" in redis.get("security_opt", [])
