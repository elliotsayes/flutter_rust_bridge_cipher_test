// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.62.1.
// ignore_for_file: non_constant_identifier_names, unused_element, duplicate_ignore, directives_ordering, curly_braces_in_flow_control_structures, unnecessary_lambdas, slash_for_doc_comments, prefer_const_literals_to_create_immutables, implicit_dynamic_list_literal, duplicate_import, unused_import, unnecessary_import, prefer_single_quotes, prefer_const_constructors, use_super_parameters, always_use_package_imports, annotate_overrides, invalid_use_of_protected_member, constant_identifier_names, invalid_use_of_internal_member

import 'bridge_generated.io.dart'
    if (dart.library.html) 'bridge_generated.web.dart';
import 'dart:convert';
import 'dart:async';
import 'package:meta/meta.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';

abstract class Native {
  Future<Platform> platform({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kPlatformConstMeta;

  Future<bool> rustReleaseMode({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRustReleaseModeConstMeta;

  Stream<Uint8List> createStream(
      {required Uint8List key,
      required Uint8List iv,
      required int chunkSize,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCreateStreamConstMeta;

  Future<void> processData({required Uint8List data, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kProcessDataConstMeta;

  Future<void> processDataLoop({required int times, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kProcessDataLoopConstMeta;
}

enum Platform {
  Unknown,
  Android,
  Ios,
  Windows,
  Unix,
  MacIntel,
  MacApple,
  Wasm,
}
