use super::*;

#[test]
fn bookmark_store_survives_reopen_and_ungroups_on_group_delete() {
    let path = super::super::tests::unique_tmp_dir("bookmarks").join("local_chat.db");
    let db = ChatDb::open(&path).unwrap();
    let group = DBookmarkGroup::new("Links");
    insert_bookmark_group(&db, &group);
    let bookmark = DBookmark::new("https://example.com", &group.id);
    insert_bookmark(&db, &bookmark);
    assert_eq!(get_bookmarks_by_group_id(&db, &group.id).len(), 1);
    drop(db);

    let db = ChatDb::open(&path).unwrap();
    assert_eq!(get_bookmarks(&db).len(), 1);
    assert_eq!(get_bookmark_groups(&db).len(), 1);
    delete_bookmark_group(&db, &group.id);
    let ungrouped = get_bookmark_by_id(&db, &bookmark.id).unwrap();
    assert_eq!(ungrouped.group_id, "");
    assert!(get_bookmark_group_by_id(&db, &group.id).is_none());
    assert_eq!(delete_bookmarks(&db, &[bookmark.id]), 1);
    assert!(get_bookmarks(&db).is_empty());
}
