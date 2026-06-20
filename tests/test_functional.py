from sqli.dao.student import Student

from tests.helpers import BCRYPT_HASH, FakeConn, FakeCursor, make_user, run


def test_create_student_runs_an_insert():
    cur = FakeCursor()
    run(Student.create(FakeConn(cur), "Alice"))
    query, params = cur.calls[0]
    assert "insert into students" in query.lower()
    assert "Alice" in query or "Alice" in str(params)


def test_wrong_password_is_rejected():
    assert make_user(BCRYPT_HASH).check_password("not-the-password") is False
