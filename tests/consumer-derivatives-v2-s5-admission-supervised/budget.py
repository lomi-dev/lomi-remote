"""One512MiB raw budget across all five work directories, no budget reset."""
PAIR=64*1024**2
TOTAL=512*1024**2
CLEANUP=128*1024**2


class SharedBudget:
    def __init__(self, policy_class, **policy_kwargs):
        self.policy_class=policy_class;self.policy_kwargs=policy_kwargs
        self.tokens={};self.high_water=0;self.failed=False;self.views=[]
    def view(self):
        view=CasePolicy(self,self.policy_class(**self.policy_kwargs));self.views.append(view);return view
    def metadata(self):
        return dict(rawLogLogicalReservationBytes=TOTAL,cleanupReservedBytes=CLEANUP,
            currentReservedBytes=len(self.tokens)*PAIR,highWaterReservedBytes=self.high_water,
            caseViews=len(self.views),qualificationAllowed=not self.failed)


class CasePolicy:
    def __init__(self,pool,local):self.pool=pool;self.local=local
    def prepare(self,work):return self.local.prepare(work)
    def install(self):return self.local.install()
    def admit_fixture_files(self,data):return self.local.admit_fixture_files(data)
    def reserve(self,name,stdout,stderr,*,cleanup=False):
        try:token=self.local.reserve(name,stdout,stderr,cleanup=cleanup)
        except BaseException:self.pool.failed=True;raise
        pool=self.pool
        if (len(pool.tokens)+1)*PAIR > (TOTAL if cleanup else TOTAL-CLEANUP):
            pool.failed=True
            # No launch/open has occurred; public release verifies both absent.
            self.local.release(token)
            raise ValueError('shared five-cluster raw-log capacity exhausted')
        pool.tokens[id(token)]=(self,token)
        pool.high_water=max(pool.high_water,len(pool.tokens)*PAIR)
        return token
    def release(self,token):
        if self.pool.tokens.get(id(token))!=(self,token):
            self.pool.failed=True;raise ValueError('unknown shared raw-log token')
        try:self.local.release(token)
        except BaseException:self.pool.failed=True;raise
        del self.pool.tokens[id(token)]
    def metadata(self):
        value=self.local.metadata()
        value.update(currentReservedBytes=len(self.pool.tokens)*PAIR,
            highWaterReservedBytes=self.pool.high_water,sharedAcrossFiveClusters=True)
        return value
