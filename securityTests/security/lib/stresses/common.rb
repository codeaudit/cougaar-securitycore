# Loads common stresses

commonStresses = [
  'printDotsOnCougaarEvents'
  ]

commonStresses.each {|stress| require "security/stresses/#{stress}"}

