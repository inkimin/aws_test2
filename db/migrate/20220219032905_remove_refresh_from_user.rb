class RemoveRefreshFromUser < ActiveRecord::Migration[7.0]
  def change
    remove_column :users, :refresh, :json
  end
end
