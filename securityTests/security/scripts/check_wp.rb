
insert_before :wait_for_initialization do
  do_action "TestWPRegistration"
end

insert_before "StopSociety" do
  do_action "StopTestWPRegistration"
end
