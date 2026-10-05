"""Synthetic dependency and license contracts; manifests are never executed."""
import json
import unittest

from general_auditor.config import default_profile
from general_auditor.repository_policy import _dependencies, _metadata_license, evaluate


class DependencyFormatTests(unittest.TestCase):
    def test_npm_retains_all_dependency_groups_and_bundles(self):
        data = {key: {key + '-package': '*'} for key in (
            'dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies')}
        data.update(bundledDependencies=['bundled'], bundleDependencies={'bundle': '*'})
        self.assertEqual({key+'-package' for key in data if key not in {'bundledDependencies', 'bundleDependencies'}} | {'bundled', 'bundle'},
                         _dependencies('package.json', json.dumps(data)))

    def test_python_project_optional_build_and_poetry_groups(self):
        source = '''[project]
dependencies = ["requests[security]>=2; python_version >= '3'", "direct @ https://example.invalid/direct.whl"]
[project.optional-dependencies]
test = ["pytest>=8"]
[build-system]
requires = ["setuptools>=68", "wheel"]
[tool.poetry.dependencies]
python = "^3.11"
rich = "*"
[tool.poetry.dev-dependencies]
ruff = "*"
[tool.poetry.group.docs.dependencies]
sphinx = "*"
'''
        self.assertEqual({'requests','direct','pytest','setuptools','wheel','rich','ruff','sphinx'},
                         _dependencies('pyproject.toml', source))

    def test_cargo_top_level_target_workspace_and_renamed_package(self):
        source = '''[dependencies]
serde = "1"
renamed = { package = "actual", version = "1" }
[dev-dependencies]
fixture = "1"
[build-dependencies]
cc = "1"
[target.'cfg(unix)'.dependencies]
libc = "1"
[workspace.dependencies]
shared = "1"
'''
        self.assertEqual({'serde','renamed','actual','fixture','cc','libc','shared'}, _dependencies('Cargo.toml', source))

    def test_cmake_four_package_declarations_ignore_comments_and_strings(self):
        source = '''# find_package(CommentOnly)
#[[ FetchContent_Declare(BlockCommentOnly) ]]
message("find_package(StringOnly)")
find_package(Threads REQUIRED)
FetchContent_Declare(fmt URL "https://example.invalid/fmt.tar.gz")
ExternalProject_Add(dep-prefix URL "https://example.invalid/dep.tar.gz")
CPMAddPackage(NAME Catch2 VERSION 3.0)
'''
        self.assertEqual({'Threads','fmt','dep-prefix','Catch2'}, _dependencies('CMakeLists.txt', source))

    def test_requirements_extract_names_not_url_specifiers_markers_or_options(self):
        source = '''# Documentation
requests[security]>=2; python_version > "3.10"
direct @ https://example.invalid/package.whl
-r extra-requirements.txt
--index-url https://example.invalid/simple
./local-source
'''
        self.assertEqual({'requests','direct'}, _dependencies('requirements-dev.txt', source))

    def test_pubspec_overrides_and_nested_sources_do_not_become_package_names(self):
        source = '''name: fixture
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0
dev_dependencies:
  flutter_test:
    sdk: flutter
dependency_overrides:
  custom:
    git:
      url: https://example.invalid/custom.git
flutter:
  uses-material-design: true
'''
        self.assertEqual({'flutter','http','flutter_test','custom'}, _dependencies('pubspec.yaml', source))

    def test_go_requires_only_not_module_replace_or_exclude(self):
        source = '''module example.invalid/self
go 1.22
require example.invalid/single v1.0.0
require (
  example.invalid/first v1.1.0 // indirect
  example.invalid/second v2.0.0
)
replace example.invalid/old v1.0.0 => example.invalid/new v1.0.0
exclude example.invalid/excluded v1.0.0
'''
        self.assertEqual({'example.invalid/single','example.invalid/first','example.invalid/second'}, _dependencies('go.mod', source))

    def test_swift_extracts_named_and_url_identities_not_whole_expressions(self):
        source = '''// .package(url: "https://example.invalid/comment.git")
let packages = [
.package(name: "Named", url: "https://example.invalid/repository.git", from: "1.0.0"),
.package(url: "https://example.invalid/dotted.name.git", .upToNextMajor(from: "2.0.0")),
.package(path: "../local-package")]
'''
        self.assertEqual({'Named','repository','dotted.name','local-package'}, _dependencies('Package.swift', source))

    def test_vcpkg_string_objects_and_feature_packages(self):
        source = json.dumps({'dependencies':['fmt', {'name':'boost','features':['system']}],
                             'features':{'network':{'dependencies':['curl']}}})
        self.assertEqual({'fmt','boost','curl'}, _dependencies('vcpkg.json', source))

    def test_malformed_declarations_do_not_return_empty_success(self):
        cases = [('package.json','{"dependencies":'), ('package.json','{"dependencies":23}'),
                 ('pyproject.toml','[project\n'), ('pyproject.toml','[project]\ndependencies = "invalid"'),
                 ('Cargo.toml','[dependencies]\nthing = '), ('CMakeLists.txt','find_package(Missing'),
                 ('go.mod','require (\nexample.invalid/item v1.0.0'),
                 ('Package.swift','.package(url: "https://example.invalid/name.git"'),
                 ('vcpkg.json','{"dependencies":[12]}'), ('pubspec.yaml','dependencies: [broken]'),
                 ('requirements.txt','??? invalid requirement')]
        for path, text in cases:
            with self.subTest(path=path,text=text):
                with self.assertRaises(ValueError): _dependencies(path,text)


class LicenseFormatTests(unittest.TestCase):
    def test_package_and_pubspec_license_values(self):
        self.assertEqual(['Apache-2.0'], _metadata_license('package.json','{"license":"Apache-2.0"}'))
        self.assertIn('Apache-2.0', _metadata_license('package.json','{"license":{"type":"Apache-2.0"}}')[0])
        self.assertEqual(['Apache-2.0'], _metadata_license('pubspec.yaml', 'license: "Apache-2.0" # approved\n'))
        self.assertEqual([None], _metadata_license('package.json','{}'))

    def test_all_toml_license_fields_including_poetry_must_be_checked(self):
        values = _metadata_license('pyproject.toml', '[project]\nlicense = {text = "Apache-2.0"}\n[tool.poetry]\nlicense = "MIT"\n')
        self.assertEqual(2,len(values))
        self.assertIn('Apache-2.0',values[0])
        self.assertEqual('MIT',values[1])
        self.assertEqual(['Apache-2.0'], _metadata_license('pyproject.toml','[tool.poetry]\nlicense="Apache-2.0"'))
        self.assertEqual([None], _metadata_license('pyproject.toml','[project]\nname="demo"'))

    def test_invalid_metadata_is_not_missing_or_valid_license(self):
        for path,text in [('package.json','{'),('pyproject.toml','license = '),('pubspec.yaml','license: "unterminated')]:
            with self.subTest(path=path):
                with self.assertRaises(ValueError): _metadata_license(path,text)

    def evaluate_files(self,policy,files):
        profile=default_profile('Example/Source');profile['repository_policy']=policy
        return evaluate('Example/Source',profile,[{'path':p,'kind':'blob'} for p in files],files.__getitem__,
                        {'head':'a'*40,'branch_refs':[],'commit_metadata':[]})

    def test_malformed_required_manifest_reports_incomplete_redacted_coverage(self):
        files={'package.json':'{"dependencies": "PRIVATE_SOURCE_VALUE"}',
               'DEPENDENCY-USAGE.md':'dependency commercial authorization usage boundary'}
        result=self.evaluate_files({'dependencies':{'boundary_files':['DEPENDENCY-USAGE.md']}},files)
        self.assertTrue(result['coverage']['incomplete'])
        self.assertIn('repository.dependency-boundary-evidence',result['coverage']['blocking'])
        self.assertNotIn('PRIVATE_SOURCE_VALUE',json.dumps(result))

    def test_missing_boundary_does_not_suppress_manifest_signals_or_parse_failures(self):
        result = self.evaluate_files({'dependencies': {'boundary_files': ['DEPENDENCY-USAGE.md']}},
                                     {'package.json': '{"description":"commercial license","dependencies":23}'})
        self.assertIn('repository.dependency-boundary-evidence', result['coverage']['blocking'])
        self.assertTrue(result['coverage']['incomplete'])
        signals = [row for row in result['findings'] if row['rule'] == 'repository.dependency-commercial-signal']
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]['severity'], 'warning')

    def test_conflicting_license_and_invalid_metadata_are_not_certified(self):
        policy={'license':{'metadata_files':['pyproject.toml']}}
        files={'LICENSE':'Apache License Version 2.0','README.md':'Apache License Version 2.0',
               'pyproject.toml':'[project]\nlicense="Apache-2.0"\n[tool.poetry]\nlicense="MIT"'}
        result=self.evaluate_files(policy,files)
        self.assertIn('repository.license-evidence',result['coverage']['blocking'])
        files['pyproject.toml']='[project\n'
        result=self.evaluate_files(policy,files)
        self.assertTrue(result['coverage']['incomplete'])
        self.assertIn('repository.license-evidence',result['coverage']['blocking'])
