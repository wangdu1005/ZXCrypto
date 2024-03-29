Pod::Spec.new do |s|

  s.name         = "ZXCrypto"
  s.version      = "1.0.1"
  s.summary      = "A simple RSA crypto lib."
  s.description  = "A simple RSA crypto lib. Reference: SwiftRSA & BlueRSA"

  s.homepage     = "https://github.com/wangdu1005"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author       = "ZX"

  s.platform     = :ios, "9.0"
  s.source       = { :git => "https://wangdu1005@bitbucket.org/wangdu1005/zxcrypto.git", :tag => "#{s.version}" }
  s.source_files  = "ZXCrypto/**/*.{swift,h,m}"
  s.swift_version = "4.2" 

end
