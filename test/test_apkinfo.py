import unittest
from unittest.mock import patch, MagicMock

from c2hunt.analysis import apkinfo


class TestApkInfoUtils(unittest.TestCase):
    def test_is_valid_apk_true(self):
        with patch('androguard.core.androconf.is_android', return_value="APK"):
            self.assertTrue(apkinfo.is_valid_apk("dummy.apk"))

    def test_is_valid_apk_false(self):
        with patch('androguard.core.androconf.is_android', return_value="DEX"):
            self.assertFalse(apkinfo.is_valid_apk("dummy.dex"))

    def test_is_valid_dex_true(self):
        with patch('androguard.core.androconf.is_android', return_value="DEX"):
            self.assertTrue(apkinfo.is_valid_dex("dummy.dex"))

    def test_is_valid_dex_false(self):
        with patch('androguard.core.androconf.is_android', return_value="APK"):
            self.assertFalse(apkinfo.is_valid_dex("dummy.apk"))

    def test_exclude_package(self):
        with patch('c2hunt.analysis.apkinfo.EXCLUDE_PACKAGE', ["com.example", "androidx"]):
            self.assertTrue(apkinfo.exclude_package("com.example.Foo"))
            self.assertTrue(apkinfo.exclude_package("androidx.bar.Baz"))
            self.assertFalse(apkinfo.exclude_package("org.else.Class"))

    def test_print_method_smali(self):
        mock_ins = MagicMock()
        mock_ins.__str__.return_value = "smali_code"
        mock_method = MagicMock()
        mock_method.get_instructions_idx.return_value = [(0, mock_ins), (1, mock_ins)]
        mock_method_analysis = MagicMock()
        mock_method_analysis.get_method.return_value = mock_method
        with patch('builtins.print') as mock_print:
            apkinfo.print_method_smali(mock_method_analysis)
            mock_print.assert_any_call(mock_ins)

    def test_print_c2c(self):
        # 依照 print_c2c 的 op_stack 實作調整順序
        mock_ins1 = MagicMock()
        mock_ins1.__str__.return_value = "move-result"
        mock_ins2 = MagicMock()
        mock_ins2.__str__.return_value = "const-string v0, \"http://c2.com\""
        mock_method = MagicMock()
        mock_method.get_instructions_idx.return_value = [(0, mock_ins1), (1, mock_ins2)]
        mock_method_analysis = MagicMock()
        mock_method_analysis.get_method.return_value = mock_method
        with patch('builtins.print') as mock_print, \
                patch('c2hunt.analysis.apkinfo.CONST_STRING', "const-string"):
            apkinfo.print_c2c(mock_method_analysis)
            mock_print.assert_any_call("http://c2.com")

    def test_print_all_smali(self):
        item = MagicMock()
        item.full_name = "A->foo"
        mock_apkinfo = MagicMock()
        mock_apkinfo.get_external_methods.return_value = [item]
        with patch('click.secho') as mock_secho, \
                patch('c2hunt.analysis.apkinfo.print_method_smali') as mock_pms, \
                patch('builtins.print') as mock_print:
            apkinfo.print_all_smali(mock_apkinfo)
            mock_secho.assert_called_with("[INFO] smali from: [A->foo]", fg="cyan")
            mock_pms.assert_called_with(item)
            mock_print.assert_any_call("=" * 80)


class TestAPKinfoClass(unittest.TestCase):
    @patch('c2hunt.analysis.apkinfo.is_valid_apk', return_value=True)
    @patch('c2hunt.analysis.apkinfo.AnalyzeAPK')
    def test_init_apk(self, mock_analyzeapk, mock_is_apk):
        mock_analyzeapk.return_value = ("apkobj", "dvmobj", MagicMock())
        info = apkinfo.APKinfo("test.apk")
        self.assertEqual(info.filename, "test.apk")
        self.assertEqual(info.apk, "apkobj")
        self.assertEqual(info.dvm, "dvmobj")
        self.assertIsNotNone(info.analysis)

    @patch('c2hunt.analysis.apkinfo.is_valid_apk', return_value=False)
    @patch('c2hunt.analysis.apkinfo.is_valid_dex', return_value=True)
    @patch('c2hunt.analysis.apkinfo.AnalyzeDex')
    def test_init_dex(self, mock_analyzedex, mock_is_dex, mock_is_apk):
        mock_analyzedex.return_value = ("dexobj", "dvmobj", MagicMock())
        info = apkinfo.APKinfo("test.dex")
        self.assertEqual(info.filename, "test.dex")
        self.assertIsNone(info.apk)
        self.assertIsNone(info.dvm)
        self.assertIsNotNone(info.analysis)

    @patch('c2hunt.analysis.apkinfo.is_valid_apk', return_value=False)
    @patch('c2hunt.analysis.apkinfo.is_valid_dex', return_value=False)
    def test_init_invalid(self, mock_is_dex, mock_is_apk):
        with self.assertRaises(ValueError):
            apkinfo.APKinfo("invalid.file")

    def test_external_methods_and_get_external_methods(self):
        # Setup fake analysis and methods
        mock_method1 = MagicMock()
        mock_method1.is_external.return_value = False
        mock_method1.class_name = "com.valid.Foo"

        mock_method2 = MagicMock()
        mock_method2.is_external.return_value = True
        mock_method2.class_name = "androidx.invalid"

        mock_analysis = MagicMock()
        mock_analysis.get_methods.return_value = [mock_method1, mock_method2]

        info = apkinfo.APKinfo.__new__(apkinfo.APKinfo)
        info.analysis = mock_analysis

        # Test external_methods
        result = info.external_methods
        self.assertIn(mock_method1, result)
        self.assertNotIn(mock_method2, result)

        # Patch exclude_package for get_external_methods
        with patch('c2hunt.analysis.apkinfo.exclude_package', return_value=False):
            result2 = info.get_external_methods()
            self.assertIn(mock_method1, result2)
        with patch('c2hunt.analysis.apkinfo.exclude_package', return_value=True):
            result2 = info.get_external_methods()
            self.assertNotIn(mock_method1, result2)

    def test_get_string_analysis(self):
        mock_analysis = MagicMock()
        mock_analysis.get_strings.return_value = ["A", "B"]
        info = apkinfo.APKinfo.__new__(apkinfo.APKinfo)
        info.analysis = mock_analysis
        result = info.get_string_analysis()
        self.assertEqual(result, {"A", "B"})


if __name__ == "__main__":
    unittest.main()
