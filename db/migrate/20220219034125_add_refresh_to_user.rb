class AddRefreshToUser < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :refresh, :string
  end
end
