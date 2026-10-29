from app.services.inventory_upload_pipeline import BoundedInventoryUpload


def test_deduplicate_and_preserve_failures():
    def upload(n):
        if n['path'] == 'bad':
            raise OSError('unreadable')
        return {'source_id': n['source_id'], 'path': n['path'],
                'object_uri': 's3://evidence/' + n['path']}
    pipe = BoundedInventoryUpload(upload, workers=2, max_pending=2)
    assert pipe.submit({'source_id': 'source-1', 'path': 'good', 'inode': 5})
    assert not pipe.submit({'source_id': 'source-1', 'path': 'good', 'inode': 5})
    assert pipe.submit({'source_id': 'source-1', 'path': 'bad', 'inode': 6})
    successes, failures = pipe.finish()
    assert len(successes) == 1
    assert len(failures) == 1 and failures[0]['path'] == 'bad'
