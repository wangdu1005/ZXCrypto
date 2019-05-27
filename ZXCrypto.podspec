Pod::Spec.new do |s|

  s.name         = "ZXCrypto"
  s.version      = "0.0.1"
  s.summary      = "A simple RSA crypto lib."
  s.description  = "A simple RSA crypto lib. Reference: SwiftRSA & BlueRSA"

  s.homepage     = "https://github.com/wangdu1005"
  s.license      = "MIT"
  s.author       = "ZX"

  s.platform     = :ios
  # s.source       = { :git => "http://EXAMPLE/ZXCrypto.git", :tag => "#{s.version}" }
  s.source       = { :path => '.' }
  s.source_files  = "ZXCrypto"
  s.swift_version = "4.2" 

end
