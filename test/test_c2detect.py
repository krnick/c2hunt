import unittest
from typing import List

from c2hunt.c2cdetect import C2Detect


# Mock instruction object to simulate ins.get_name() and ins.get_output()
class MockInstruction:
    def __init__(self, name: str, output: str = ""):
        self._name = name
        self._output = output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


# Mock method object to simulate method_analysis.get_method().get_instructions_idx()
class MockMethod:
    def __init__(self, instructions: List[MockInstruction]):
        self._instructions = instructions

    def get_instructions_idx(self):
        return ((idx, ins) for idx, ins in enumerate(self._instructions))


class MockMethodAnalysis:
    def __init__(self, instructions: List[MockInstruction]):
        self._method = MockMethod(instructions)

    def get_method(self):
        return self._method


class TestC2Detect(unittest.TestCase):
    def setUp(self):
        self.opcode_dict = {"invoke-virtual": 3, "if-eq": 2}
        self.detector = C2Detect(self.opcode_dict)

    def test_threshold_not_reached(self):
        instructions = [
            MockInstruction("invoke-virtual"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
        ]
        method_analysis = MockMethodAnalysis(instructions)
        result = self.detector.find_c2_command_method(method_analysis)
        self.assertIsNone(result)
        self.assertEqual(self.detector.get_counter(), {"invoke-virtual": 2, "if-eq": 1})

    def test_threshold_exactly_reached(self):
        instructions = [
            MockInstruction("invoke-virtual"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
        ]
        method_analysis = MockMethodAnalysis(instructions)
        result = self.detector.find_c2_command_method(method_analysis)
        self.assertIs(result, method_analysis)
        self.assertEqual(self.detector.get_counter(), {"invoke-virtual": 3, "if-eq": 2})

    def test_threshold_exceeded(self):
        instructions = [
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
            MockInstruction("invoke-virtual"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
        ]
        method_analysis = MockMethodAnalysis(instructions)
        result = self.detector.find_c2_command_method(method_analysis)
        self.assertIs(result, method_analysis)
        self.assertEqual(self.detector.get_counter(), {"invoke-virtual": 4, "if-eq": 3})

    def test_other_opcodes_ignored(self):
        instructions = [
            MockInstruction("invoke-virtual"),
            MockInstruction("nop"),
            MockInstruction("if-eq"),
            MockInstruction("add-int"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq"),
            MockInstruction("invoke-virtual"),
        ]
        method_analysis = MockMethodAnalysis(instructions)
        result = self.detector.find_c2_command_method(method_analysis)
        self.assertIs(result, method_analysis)
        self.assertEqual(self.detector.get_counter(), {"invoke-virtual": 3, "if-eq": 2})

    def test_output_affects_detection(self):
        instructions = [
            MockInstruction("nop", "invoke-virtual"),  # Should be counted
            MockInstruction("if-eq"),
            MockInstruction("invoke-virtual"),
            MockInstruction("if-eq", "invoke-virtual"),  # Both counted
        ]
        method_analysis = MockMethodAnalysis(instructions)
        result = self.detector.find_c2_command_method(method_analysis)
        # "invoke-virtual" appears 3 times (1 in output), "if-eq" appears 2 times (1 in output)
        self.assertIs(result, method_analysis)
        self.assertEqual(self.detector.get_counter(), {"invoke-virtual": 3, "if-eq": 2})


if __name__ == "__main__":
    unittest.main()
