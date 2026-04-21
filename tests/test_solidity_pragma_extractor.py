from blockchain.smart_contracts.analyzer import extract_solidity_pragma_and_min_version


def test_extract_caret_version():
    src = "pragma solidity ^0.8.0; contract A {}"
    raw, min_v = extract_solidity_pragma_and_min_version(src)
    assert raw == "^0.8.0"
    assert min_v == (0, 8, 0)


def test_extract_range_version():
    src = "pragma solidity >=0.7.0 <0.9.0; contract A {}"
    raw, min_v = extract_solidity_pragma_and_min_version(src)
    assert raw == ">=0.7.0 <0.9.0"
    assert min_v == (0, 7, 0)


def test_extract_fixed_version():
    src = "pragma solidity 0.8.19; contract A {}"
    raw, min_v = extract_solidity_pragma_and_min_version(src)
    assert raw == "0.8.19"
    assert min_v == (0, 8, 19)
