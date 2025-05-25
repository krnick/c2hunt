from typing import Dict, Any, Optional


class C2Detect:
    """
    Detects whether a method contains suspicious opcodes reaching a specific threshold.
    """

    def __init__(self, opcode_dict: Dict[str, int]):
        """
        :param opcode_dict: For example, {"invoke-virtual": 10, "if-eq": 10}
        """
        self.op_threshold = opcode_dict.copy()
        self.reset_counter()

    def reset_counter(self) -> None:
        """Reset the opcode counter to zero for each opcode."""
        self.op_counter = {key: 0 for key in self.op_threshold}

    def find_c2_command_method(self, method_analysis: Any) -> Optional[Any]:
        """
        Check if all specified opcodes reach the threshold in the given method.
        If so, return method_analysis; otherwise, return None.
        :param method_analysis: Expected to have get_method().get_instructions_idx()
        """
        self.reset_counter()
        for _, ins in method_analysis.get_method().get_instructions_idx():
            instructions = "{} {}".format(ins.get_name(), ins.get_output())
            for key in self.op_counter:
                # If the opcode keyword appears in the instruction string, increment the counter.
                if key in instructions:
                    self.op_counter[key] += 1

        # Return method_analysis only if all opcodes meet their respective thresholds.
        if all(self.op_counter[k] >= self.op_threshold[k] for k in self.op_threshold):
            return method_analysis
        return None

    def get_counter(self) -> Dict[str, int]:
        """Get a copy of the current opcode counter result."""
        return self.op_counter.copy()


if __name__ == "__main__":
    pass
