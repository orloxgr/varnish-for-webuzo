"""Recoverable changes to this plugin's separate cache service only."""
import copy
import native
import service
import state

def journal_path():return state.ROOT/'resize.json'

def recover(settings_path):
    record=state.read(journal_path())
    if not record:return
    old=record['previous'];new=record['next']
    current=native.read(service.UNIT).decode()
    if current not in (service.unit(old.get('memory_mb',256)),service.unit(new['memory_mb'])):
        raise ValueError('The owned service unit was changed; cache-size recovery is pending')
    state.write(service.UNIT,service.unit(old.get('memory_mb',256)).encode());service.UNIT.chmod(0o644)
    state.save(settings_path,old)
    service.restart(old.get('memory_mb',256));journal_path().unlink()

def resize(previous,value,settings_path):
    service.memory_mb(value)
    if value==previous.get('memory_mb',256):return False
    if native.read(service.UNIT).decode()!=service.unit(previous.get('memory_mb',256)):
        raise ValueError('The owned service unit was changed')
    updated=copy.deepcopy(previous);updated['memory_mb']=value
    state.save(journal_path(),dict(previous=previous,next=updated))
    try:
        state.write(service.UNIT,service.unit(value).encode());service.UNIT.chmod(0o644)
        state.save(settings_path,updated)
        service.restart(value)
    except Exception:
        try:recover(settings_path)
        except Exception:raise RuntimeError('Cache resize failed; recovery is pending. Check the Varnish service.') from None
        raise RuntimeError('Cache resize failed; the previous size was restored. Cache contents were cleared.') from None
    journal_path().unlink()
    return True
