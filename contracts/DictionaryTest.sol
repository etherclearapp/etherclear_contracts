pragma solidity ^0.5.2;

import "./Dictionary.sol";

// Taken from https://github.com/sagivo/solidity-utils/blob/master/contracts/tester/DictionaryTest.sol
contract DictionaryTest {
    using Dictionary for Dictionary.Data;
    Dictionary.Data private dic;

    function getSize() public view returns (uint) {
        return dic.len;
    }

    function insertAfter(uint afterId, uint id, bytes memory data) public {
        dic.insertAfter(afterId, id, data);
    }

    function insertBefore(uint beforeId, uint id, bytes memory data) public {
        dic.insertAfter(beforeId, id, data);
    }

    function insertBeginning(uint id, bytes memory data) public {
        dic.insertBeginning(id, data);
    }

    function set(uint id, bytes memory data) public {
        dic.set(id, data);
    }

    function get(uint id) public view returns (bytes memory) {
        return dic.get(id);
    }

    function keys() public view returns (uint[] memory) {
        return dic.keys();
    }

    function insertEnd(uint id, bytes memory data) public {
        dic.insertEnd(id, data);
    }

    function remove(uint id) public returns (bool) {
        return dic.remove(id);
    }

    function first() public view returns (uint) {
        return dic.firstNodeId;
    }

    function next(uint id) public view returns (uint) {
        return dic.next(id);
    }

    function prev(uint id) public view returns (uint) {
        return dic.prev(id);
    }
}
