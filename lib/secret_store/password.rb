require 'bcrypt'
BCrypt::Engine.cost = 14

module SecretStore
  class Password
    attr_reader :password

    def initialize hashed_password
      @password = BCrypt::Password.new( hashed_password.to_s )
    end

    def matches plain_password
      @password == plain_password
    end

    def self.create secret
      self.new( BCrypt::Password.create( secret ) )
    end

    def to_h
      Hash[
        :hashed_password => password.to_s
      ]
    end

    def self.from_h h
      self.new( h[:hashed_password] )
    end
  end
end
