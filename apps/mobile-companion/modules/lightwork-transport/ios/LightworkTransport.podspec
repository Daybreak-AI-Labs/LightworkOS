Pod::Spec.new do |s|
  s.name = 'LightworkTransport'
  s.version = '0.1.0'
  s.summary = 'Bounded, cancellable native transport for the Lightwork companion'
  s.description = s.summary
  s.license = { :type => 'Apache-2.0' }
  s.author = 'The Lightwork Authors'
  s.homepage = 'https://github.com/Daybreak-AI-Labs/LightworkOS'
  s.source = { :git => 'https://github.com/Daybreak-AI-Labs/LightworkOS.git' }
  s.platforms = { :ios => '15.1' }
  s.swift_version = '5.9'
  s.static_framework = true
  s.dependency 'ExpoModulesCore'
  s.source_files = '**/*.swift'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
